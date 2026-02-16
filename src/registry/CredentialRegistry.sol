// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {IScorer} from "./IScorer.sol";
import {DefaultScorer} from "../scoring/DefaultScorer.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {ReentrancyGuard} from "openzeppelin/security/ReentrancyGuard.sol";

/// @title CredentialRegistry
/// @notice Main contract for the BringID privacy-preserving credential system.
///
/// Users register credentials via verifier-signed attestations, then prove membership
/// using Semaphore zero-knowledge proofs. Each credential group carries a score;
/// the `submitProofs()` function validates proofs (consuming nullifiers) and aggregates scores.
///
/// Per-app Semaphore groups: each (credentialGroup, app) pair gets its own Semaphore
/// group, created lazily on first credential registration. Since Semaphore enforces
/// per-group nullifier uniqueness, separate groups per app naturally prevent cross-app
/// proof replay.
contract CredentialRegistry is ICredentialRegistry, Ownable2Step, ReentrancyGuard {
    using ECDSA for bytes32;

    /// @notice The Semaphore contract used for group management and ZK proof verification.
    ISemaphore public immutable SEMAPHORE;

    /// @notice Registry of trusted verifiers that can sign attestations.
    /// Each verifier is an ECDSA signer whose signatures are accepted for
    /// credential attestations. Supports multiple verification methods
    /// (TLSN, OAuth, zkPassport, etc.).
    mapping(address => bool) public trustedVerifiers;

    /// @notice Registry of credential groups. Each group has a status (UNDEFINED / ACTIVE / SUSPENDED).
    mapping(uint256 credentialGroupId => CredentialGroup) public credentialGroups;

    /// @notice Registry of apps. Each app has a status (UNDEFINED / ACTIVE / SUSPENDED).
    /// Apps must be registered before users can register credentials or submit proofs for them.
    mapping(uint256 appId => App) public apps;

    /// @notice Maps (credentialGroupId, appId) to the Semaphore group ID for that pair.
    /// Created lazily on first credential registration for the pair.
    mapping(uint256 credentialGroupId => mapping(uint256 appId => uint256 semaphoreGroupId)) public appSemaphoreGroups;

    /// @notice Tracks whether a Semaphore group has been created for a (credentialGroup, app) pair.
    mapping(uint256 credentialGroupId => mapping(uint256 appId => bool)) public appSemaphoreGroupCreated;

    /// @notice Per-credential state keyed by registration hash.
    /// For family groups (familyId > 0): key = keccak256(registry, familyId, 0, credentialId, appId)
    /// — all groups in the same family share one slot, preventing double registration.
    /// For standalone groups (familyId == 0): key = keccak256(registry, 0, credentialGroupId, credentialId, appId).
    /// The `commitment` field persists across expiry/removal for nullifier continuity.
    mapping(bytes32 registrationHash => CredentialRecord) public credentials;

    /// @notice Maximum age (in seconds) an attestation is accepted. Default 30 minutes.
    uint256 public attestationValidityDuration = 30 minutes;

    /// @notice Array of all registered credential group IDs (for enumeration).
    uint256[] public credentialGroupIds;

    /// @notice Auto-incrementing app ID counter. Next app will get this ID.
    uint256 public nextAppId = 1;

    /// @notice Address of the DefaultScorer contract deployed by the constructor.
    address public defaultScorer;

    /// @param semaphore_ Address of the deployed Semaphore contract.
    /// @param trustedVerifier_ Address of the initial trusted verifier to add.
    constructor(ISemaphore semaphore_, address trustedVerifier_) {
        require(trustedVerifier_ != address(0), "BID::invalid trusted verifier");
        SEMAPHORE = semaphore_;
        trustedVerifiers[trustedVerifier_] = true;
        emit TrustedVerifierUpdated(trustedVerifier_, true);

        DefaultScorer _scorer = new DefaultScorer(msg.sender);
        defaultScorer = address(_scorer);
    }

    // ──────────────────────────────────────────────
    //  View helpers
    // ──────────────────────────────────────────────

    /// @notice Returns true if the credential group is currently active.
    /// @param credentialGroupId_ The credential group ID to check.
    function credentialGroupIsActive(uint256 credentialGroupId_) public view returns (bool) {
        return credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE;
    }

    /// @notice Returns true if the app is currently active.
    /// @param appId_ The app ID to check.
    function appIsActive(uint256 appId_) public view returns (bool) {
        return apps[appId_].status == AppStatus.ACTIVE;
    }

    /// @notice Returns all registered credential group IDs.
    function getCredentialGroupIds() external view returns (uint256[] memory) {
        return credentialGroupIds;
    }

    // ──────────────────────────────────────────────
    //  Credential registration
    // ──────────────────────────────────────────────

    /// @notice Register a credential using a verifier-signed attestation (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main registerCredential implementation.
    ///      The signature can be reused across all networks since it signs the attestation
    ///      struct which includes the registry address.
    /// @param attestation_ The attestation containing credential details and Semaphore commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function registerCredential(Attestation memory attestation_, bytes memory signature_) public {
        require(signature_.length == 65, "BID::invalid attestation sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        registerCredential(attestation_, v, r, s);
    }

    /// @notice Register a credential using a verifier-signed attestation.
    /// @dev Validates the attestation and adds the user's Semaphore commitment to the
    ///      per-app Semaphore group. The flow:
    ///      1. Compute registration hash from (registry, credentialGroupId, credentialId, appId).
    ///      2. Verify the credential group and app are active.
    ///      3. Verify the attestation was signed by a trusted verifier.
    ///      4. Lazily create the per-app Semaphore group if needed.
    ///      5. Mark the credential as registered and add the commitment to the Semaphore group.
    /// @param attestation_ The attestation struct containing:
    ///        - registry: must match this contract's address
    ///        - credentialGroupId: the group to join
    ///        - credentialId: app-specific credential identity (used for dedup)
    ///        - appId: the app this credential is for
    ///        - semaphoreIdentityCommitment: the Semaphore identity commitment to register
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function registerCredential(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s) public {
        (address signer, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];
        require(!cred.registered, "BID::already registered");

        // Lazily create the per-app Semaphore group
        uint256 semaphoreGroupId = _ensureAppSemaphoreGroup(attestation_.credentialGroupId, attestation_.appId);

        cred.registered = true;
        cred.credentialGroupId = attestation_.credentialGroupId;
        cred.commitment = attestation_.semaphoreIdentityCommitment;
        SEMAPHORE.addMember(semaphoreGroupId, attestation_.semaphoreIdentityCommitment);

        uint256 validityDuration = credentialGroups[attestation_.credentialGroupId].validityDuration;
        uint256 expiresAt;
        if (validityDuration > 0) {
            expiresAt = block.timestamp + validityDuration;
            cred.expiresAt = expiresAt;
        }

        emit CredentialRegistered(
            attestation_.credentialGroupId,
            attestation_.appId,
            attestation_.semaphoreIdentityCommitment,
            attestation_.credentialId,
            registrationHash,
            signer,
            expiresAt
        );
    }

    // ──────────────────────────────────────────────
    //  Credential renewal
    // ──────────────────────────────────────────────

    /// @notice Renew a previously-registered credential (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main renewCredential implementation.
    /// @param attestation_ The attestation (commitment must match the stored one).
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function renewCredential(Attestation memory attestation_, bytes memory signature_) public {
        require(signature_.length == 65, "BID::invalid attestation sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        renewCredential(attestation_, v, r, s);
    }

    /// @notice Renew a previously-registered credential.
    /// @dev Re-activates an expired/removed credential or extends an active one.
    ///      The identity commitment must remain the same (preserving nullifier continuity).
    ///      If the credential was removed from the Semaphore group, it is re-added.
    ///      The validity duration is always reset from the current block timestamp.
    /// @param attestation_ The attestation struct. The semaphoreIdentityCommitment must match
    ///        the stored commitment from the original registration.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function renewCredential(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s) public {
        (address signer, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];
        require(cred.registered, "BID::not registered");
        require(attestation_.semaphoreIdentityCommitment == cred.commitment, "BID::commitment mismatch");
        require(cred.pendingRecovery.executeAfter == 0, "BID::recovery pending");

        require(attestation_.credentialGroupId == cred.credentialGroupId, "BID::group mismatch");

        // Re-add to Semaphore if credential was expired and removed
        if (cred.expired) {
            uint256 semaphoreGroupId = appSemaphoreGroups[attestation_.credentialGroupId][attestation_.appId];
            SEMAPHORE.addMember(semaphoreGroupId, cred.commitment);
            cred.expired = false;
        }

        // Reset validity duration
        uint256 validityDuration = credentialGroups[attestation_.credentialGroupId].validityDuration;
        uint256 expiresAt;
        if (validityDuration > 0) {
            expiresAt = block.timestamp + validityDuration;
            cred.expiresAt = expiresAt;
        } else {
            cred.expiresAt = 0;
        }

        emit CredentialRenewed(
            attestation_.credentialGroupId,
            attestation_.appId,
            cred.commitment,
            attestation_.credentialId,
            registrationHash,
            signer,
            expiresAt
        );
    }

    // ──────────────────────────────────────────────
    //  Proof validation
    // ──────────────────────────────────────────────

    /// @notice Submits a single credential group proof, consuming the nullifier.
    /// @dev The validation flow:
    ///      1. Check the credential group and app are active.
    ///      2. Verify scope binding: scope must equal keccak256(msg.sender, context_),
    ///         which ties the proof to the caller and prevents replay across addresses.
    ///      3. Require that the per-app Semaphore group exists.
    ///      4. Validate the Semaphore proof on-chain (proves group membership).
    ///         Semaphore also enforces per-group nullifier uniqueness internally.
    /// @param context_ Application-defined context value. Combined with msg.sender to
    ///        compute the expected scope, allowing the same user to generate distinct
    ///        proofs for different contexts.
    /// @param proof_ The credential group proof containing:
    ///        - credentialGroupId: which group is being proven
    ///        - appId: which app identity was used (must be active)
    ///        - semaphoreProof: the Semaphore ZK proof (membership + nullifier)
    function submitProof(uint256 context_, CredentialGroupProof memory proof_)
        public
        nonReentrant
        returns (uint256 _score)
    {
        _score = _submitProof(context_, proof_);
    }

    /// @notice Submits multiple credential group proofs (consuming nullifiers) and returns
    ///         the sum of their scores.
    /// @dev Iterates over each proof, accumulates the group's score, and calls _submitProof()
    ///      which performs full Semaphore verification and consumes nullifiers. If any proof
    ///      is invalid, the entire transaction reverts.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to submit.
    /// @return _score The total score across all validated credential groups.
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs_)
        public
        nonReentrant
        returns (uint256 _score)
    {
        _score = 0;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _score += _submitProof(context_, proofs_[i]);
        }
    }

    /// @dev Internal implementation of submitProof. Validates the proof, consumes the
    ///      Semaphore nullifier, and returns the credential group's score from the app's scorer.
    function _submitProof(uint256 context_, CredentialGroupProof memory proof_) internal returns (uint256 _score) {
        require(
            credentialGroups[proof_.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "BID::credential group inactive"
        );
        require(apps[proof_.appId].status == AppStatus.ACTIVE, "BID::app not active");
        require(
            proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))), "BID::scope mismatch"
        );
        require(appSemaphoreGroupCreated[proof_.credentialGroupId][proof_.appId], "BID::no semaphore group");

        uint256 semaphoreGroupId = appSemaphoreGroups[proof_.credentialGroupId][proof_.appId];
        SEMAPHORE.validateProof(semaphoreGroupId, proof_.semaphoreProof);

        emit ProofValidated(proof_.credentialGroupId, proof_.appId, proof_.semaphoreProof.nullifier);

        _score = IScorer(apps[proof_.appId].scorer).getScore(proof_.credentialGroupId);
    }

    /// @notice Verifies a credential group proof without consuming the nullifier.
    /// @dev Uses Semaphore's view-only verifyProof() instead of its state-changing validateProof(),
    ///      so the proof can still be submitted later. Useful for off-chain checks
    ///      or UI validation before submitting a transaction.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proof_ The credential group proof to verify.
    /// @return True if the proof is valid.
    function verifyProof(uint256 context_, CredentialGroupProof memory proof_) public view returns (bool) {
        if (credentialGroups[proof_.credentialGroupId].status != CredentialGroupStatus.ACTIVE) return false;
        if (apps[proof_.appId].status != AppStatus.ACTIVE) return false;
        if (proof_.semaphoreProof.scope != uint256(keccak256(abi.encode(msg.sender, context_)))) return false;
        if (!appSemaphoreGroupCreated[proof_.credentialGroupId][proof_.appId]) return false;

        uint256 semaphoreGroupId = appSemaphoreGroups[proof_.credentialGroupId][proof_.appId];
        return SEMAPHORE.verifyProof(semaphoreGroupId, proof_.semaphoreProof);
    }

    /// @notice Verifies multiple credential group proofs without consuming nullifiers.
    /// @dev View-only counterpart to submitProofs(). Returns false if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs_) public view returns (bool) {
        for (uint256 i = 0; i < proofs_.length; i++) {
            if (!verifyProof(context_, proofs_[i])) return false;
        }
        return true;
    }

    /// @notice Verifies multiple proofs and returns the aggregate score without consuming nullifiers.
    /// @dev View-only counterpart to submitProofs(). Reverts if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return _score The total score across all verified credential groups.
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs_) public view returns (uint256 _score) {
        _score = 0;
        CredentialGroupProof memory _proof;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _proof = proofs_[i];
            require(verifyProof(context_, _proof), "BID::invalid proof");
            _score += IScorer(apps[_proof.appId].scorer).getScore(_proof.credentialGroupId);
        }
    }

    // ──────────────────────────────────────────────
    //  Owner-only administration
    // ──────────────────────────────────────────────

    /// @notice Creates a new credential group with the given ID.
    /// @dev The credential group ID is user-defined (not auto-incremented) and must be > 0.
    ///      Per-app Semaphore groups are created lazily during credential registration.
    ///      Scores are managed separately by Scorer contracts, not by the registry.
    /// @param credentialGroupId_ The unique identifier for this credential group (must be > 0).
    /// @param validityDuration_ Duration in seconds for which credentials in this group remain valid
    ///        (0 = no expiry).
    /// @param familyId_ Family ID (0 = standalone, >0 = family grouping). Groups in the same family
    ///        share a registration hash, so only one group per family can be active per credential per app.
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_, uint256 familyId_)
        public
        onlyOwner
    {
        require(credentialGroupId_ > 0, "BID::zero credential group ID");
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED,
            "BID::credential group exists"
        );
        CredentialGroup memory _credentialGroup =
            CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE, validityDuration_, familyId_);
        credentialGroups[credentialGroupId_] = _credentialGroup;
        credentialGroupIds.push(credentialGroupId_);
        emit CredentialGroupCreated(credentialGroupId_, _credentialGroup);
    }

    /// @notice Updates the validity duration for an existing credential group.
    /// @dev Only affects future registrations; existing credentials keep their original expiry.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param validityDuration_ New duration in seconds (0 = no expiry).
    function setCredentialGroupValidityDuration(uint256 credentialGroupId_, uint256 validityDuration_)
        public
        onlyOwner
    {
        require(
            credentialGroups[credentialGroupId_].status != CredentialGroupStatus.UNDEFINED,
            "BID::credential group not found"
        );
        credentialGroups[credentialGroupId_].validityDuration = validityDuration_;
        emit CredentialGroupValidityDurationSet(credentialGroupId_, validityDuration_);
    }

    /// @notice Updates the family ID for an existing credential group.
    /// @dev Only affects future registrations; existing registrations keep their original hash.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param familyId_ New family ID (0 = standalone, >0 = family).
    function setCredentialGroupFamily(uint256 credentialGroupId_, uint256 familyId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status != CredentialGroupStatus.UNDEFINED,
            "BID::credential group not found"
        );
        credentialGroups[credentialGroupId_].familyId = familyId_;
        emit CredentialGroupFamilySet(credentialGroupId_, familyId_);
    }

    /// @notice Updates the global attestation validity duration.
    /// @param duration_ New duration in seconds (must be > 0).
    function setAttestationValidityDuration(uint256 duration_) public onlyOwner {
        require(duration_ > 0, "BID::zero duration");
        attestationValidityDuration = duration_;
        emit AttestationValidityDurationSet(duration_);
    }

    /// @notice Suspends an active credential group, preventing new registrations and proof validations.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE,
            "BID::credential group not active"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.SUSPENDED);
    }

    /// @notice Reactivates a suspended credential group.
    /// @param credentialGroupId_ The credential group ID to activate.
    function activateCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.SUSPENDED,
            "BID::credential group not suspended"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.ACTIVE;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.ACTIVE);
    }

    /// @notice Registers a new app. Caller becomes the app admin.
    /// @dev App IDs are auto-incremented. The app uses the defaultScorer by default.
    /// @param recoveryTimelock_ The recovery timelock duration in seconds (0 to disable).
    /// @return appId_ The newly assigned app ID.
    function registerApp(uint256 recoveryTimelock_) public returns (uint256 appId_) {
        appId_ = nextAppId++;
        apps[appId_] = App(AppStatus.ACTIVE, recoveryTimelock_, msg.sender, defaultScorer);
        emit AppRegistered(appId_, msg.sender, recoveryTimelock_);
    }

    /// @notice Suspends an active app, preventing new registrations and proof validations for it.
    /// @dev Only callable by the app admin.
    /// @param appId_ The app ID to suspend.
    function suspendApp(uint256 appId_) public {
        require(apps[appId_].admin == msg.sender, "BID::not app admin");
        require(apps[appId_].status == AppStatus.ACTIVE, "BID::app not active");
        apps[appId_].status = AppStatus.SUSPENDED;
        emit AppStatusChanged(appId_, AppStatus.SUSPENDED);
    }

    /// @notice Reactivates a suspended app.
    /// @dev Only callable by the app admin.
    /// @param appId_ The app ID to activate.
    function activateApp(uint256 appId_) public {
        require(apps[appId_].admin == msg.sender, "BID::not app admin");
        require(apps[appId_].status == AppStatus.SUSPENDED, "BID::app not suspended");
        apps[appId_].status = AppStatus.ACTIVE;
        emit AppStatusChanged(appId_, AppStatus.ACTIVE);
    }

    /// @notice Adds a trusted verifier that can sign attestations.
    /// @param verifier_ The verifier address to trust (must not be zero).
    function addTrustedVerifier(address verifier_) public onlyOwner {
        require(verifier_ != address(0), "BID::invalid verifier address");
        trustedVerifiers[verifier_] = true;
        emit TrustedVerifierUpdated(verifier_, true);
    }

    /// @notice Removes a trusted verifier, revoking its ability to sign attestations.
    /// @param verifier_ The verifier address to remove (must be currently trusted).
    function removeTrustedVerifier(address verifier_) public onlyOwner {
        require(trustedVerifiers[verifier_], "BID::verifier not trusted");
        trustedVerifiers[verifier_] = false;
        emit TrustedVerifierUpdated(verifier_, false);
    }

    /// @notice Sets the recovery timelock duration for an app.
    /// @dev Only callable by the app admin. Set to 0 to disable recovery.
    /// @param appId_ The app ID to configure.
    /// @param recoveryTimelock_ The timelock duration in seconds (0 to disable recovery).
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) public {
        require(apps[appId_].admin == msg.sender, "BID::not app admin");
        require(apps[appId_].status == AppStatus.ACTIVE, "BID::app not active");
        apps[appId_].recoveryTimelock = recoveryTimelock_;
        emit AppRecoveryTimelockSet(appId_, recoveryTimelock_);
    }

    /// @notice Transfers app admin to a new address.
    /// @param appId_ The app ID.
    /// @param newAdmin_ The new admin address.
    function setAppAdmin(uint256 appId_, address newAdmin_) public {
        require(apps[appId_].admin == msg.sender, "BID::not app admin");
        require(newAdmin_ != address(0), "BID::invalid admin address");
        address oldAdmin = apps[appId_].admin;
        apps[appId_].admin = newAdmin_;
        emit AppAdminTransferred(appId_, oldAdmin, newAdmin_);
    }

    /// @notice Sets a custom scorer contract for an app.
    /// @param appId_ The app ID.
    /// @param scorer_ The scorer contract address.
    function setAppScorer(uint256 appId_, address scorer_) public {
        require(apps[appId_].admin == msg.sender, "BID::not app admin");
        require(scorer_ != address(0), "BID::invalid scorer address");
        apps[appId_].scorer = scorer_;
        emit AppScorerSet(appId_, scorer_);
    }

    // ──────────────────────────────────────────────
    //  Credential expiry
    // ──────────────────────────────────────────────

    /// @notice Removes an expired credential from its per-app Semaphore group.
    /// @dev Anyone can call this once a credential has expired. Clears registration state
    ///      so the user can re-register with a fresh attestation. Also clears any pending
    ///      recovery to avoid orphaned state.
    /// @param credentialGroupId_ The credential group the credential belongs to.
    /// @param credentialId_ The credential identity (from the attestation).
    /// @param appId_ The app the credential was registered for.
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the commitment from the Semaphore group.
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) public {
        uint256 familyId = credentialGroups[credentialGroupId_].familyId;
        bytes32 registrationHash = _registrationHash(familyId, credentialGroupId_, credentialId_, appId_);
        CredentialRecord storage cred = credentials[registrationHash];
        require(cred.registered, "BID::not registered");
        require(!cred.expired, "BID::already expired");
        require(credentialGroupId_ == cred.credentialGroupId, "BID::group mismatch");
        require(cred.pendingRecovery.executeAfter == 0, "BID::recovery pending");
        require(cred.expiresAt > 0, "BID::no expiry set");
        require(block.timestamp >= cred.expiresAt, "BID::not yet expired");

        uint256 semaphoreGroupId = appSemaphoreGroups[credentialGroupId_][appId_];
        SEMAPHORE.removeMember(semaphoreGroupId, cred.commitment, merkleProofSiblings_);

        cred.expired = true;
        // NOTE: cred.commitment is intentionally NOT cleared.
        // This forces renewal to use the same identity commitment,
        // preserving Semaphore nullifier continuity and preventing double-spend.
        delete cred.pendingRecovery;

        emit CredentialExpired(credentialGroupId_, appId_, credentialId_, registrationHash);
    }

    // ──────────────────────────────────────────────
    //  Key recovery
    // ──────────────────────────────────────────────

    /// @notice Initiates recovery for a credential (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main initiateRecovery implementation.
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the old commitment from
    ///        the Semaphore group.
    function initiateRecovery(
        Attestation memory attestation_,
        bytes memory signature_,
        uint256[] calldata merkleProofSiblings_
    ) public {
        require(signature_.length == 65, "BID::invalid attestation sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        initiateRecovery(attestation_, v, r, s, merkleProofSiblings_);
    }

    /// @notice Initiates recovery for a credential.
    /// @dev The verifier re-derives the same credentialId from the user's OAuth
    ///      credentials and signs an attestation with a new Semaphore commitment. The old
    ///      commitment is immediately removed from the Semaphore group. The new commitment
    ///      is queued with the app's timelock and can be finalized via executeRecovery().
    ///
    ///      During the timelock period the user has no valid commitment in the group
    ///      (intentional — prevents use of a compromised identity).
    /// @param attestation_ Attestation with the same credentialId but a new semaphoreIdentityCommitment.
    ///        The appId field determines which app's recovery timelock governs this recovery.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @param merkleProofSiblings_ Merkle proof siblings for the old commitment in the Semaphore group.
    function initiateRecovery(
        Attestation memory attestation_,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256[] calldata merkleProofSiblings_
    ) public {
        (, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];

        require(cred.registered, "BID::not registered");
        require(cred.pendingRecovery.executeAfter == 0, "BID::recovery already pending");
        require(apps[attestation_.appId].recoveryTimelock > 0, "BID::recovery disabled");

        // Allow same group (key recovery) or different group within the same family (group change).
        // Both go through the recovery timelock to prevent double-spend with different nullifiers.
        uint256 credFamilyId = credentialGroups[cred.credentialGroupId].familyId;
        uint256 attestFamilyId = credentialGroups[attestation_.credentialGroupId].familyId;
        require(
            attestation_.credentialGroupId == cred.credentialGroupId
                || (credFamilyId > 0 && credFamilyId == attestFamilyId),
            "BID::group mismatch"
        );

        _executeInitiateRecovery(attestation_, registrationHash, merkleProofSiblings_);
    }

    function _executeInitiateRecovery(
        Attestation memory attestation_,
        bytes32 registrationHash,
        uint256[] calldata merkleProofSiblings_
    ) internal {
        CredentialRecord storage cred = credentials[registrationHash];
        uint256 oldCommitment = cred.commitment;

        // Only remove from Semaphore if the credential hasn't been expired and removed.
        // After removeExpiredCredential, the commitment is already gone from Semaphore.
        // Use cred.credentialGroupId (not attestation) for removal — the attestation may
        // target a different group within the same family (group change).
        if (!cred.expired) {
            uint256 semaphoreGroupId = appSemaphoreGroups[cred.credentialGroupId][attestation_.appId];
            SEMAPHORE.removeMember(semaphoreGroupId, oldCommitment, merkleProofSiblings_);
        }

        uint256 executeAfter = block.timestamp + apps[attestation_.appId].recoveryTimelock;
        cred.pendingRecovery = RecoveryRequest({
            credentialGroupId: attestation_.credentialGroupId,
            appId: attestation_.appId,
            newCommitment: attestation_.semaphoreIdentityCommitment,
            executeAfter: executeAfter
        });

        emit RecoveryInitiated(
            registrationHash,
            attestation_.credentialGroupId,
            oldCommitment,
            attestation_.semaphoreIdentityCommitment,
            executeAfter
        );
    }

    /// @notice Finalizes a pending recovery after the timelock has expired.
    /// @dev Adds the new commitment to the Semaphore group, updates the stored commitment,
    ///      and clears the pending recovery. Can be called by anyone once the timelock expires.
    /// @param registrationHash_ The registration hash identifying the credential being recovered.
    function executeRecovery(bytes32 registrationHash_) public {
        CredentialRecord storage cred = credentials[registrationHash_];
        RecoveryRequest memory request = cred.pendingRecovery;
        require(request.executeAfter != 0, "BID::no pending recovery");
        require(block.timestamp >= request.executeAfter, "BID::recovery timelock not expired");

        require(
            credentialGroups[request.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "BID::credential group inactive"
        );
        require(apps[request.appId].status == AppStatus.ACTIVE, "BID::app not active");

        // Use _ensureAppSemaphoreGroup because the target group may not have a
        // Semaphore group yet (group change within a family to a never-used group).
        uint256 semaphoreGroupId = _ensureAppSemaphoreGroup(request.credentialGroupId, request.appId);
        SEMAPHORE.addMember(semaphoreGroupId, request.newCommitment);
        cred.expired = false;
        cred.commitment = request.newCommitment;
        cred.credentialGroupId = request.credentialGroupId;
        delete cred.pendingRecovery;

        emit RecoveryExecuted(registrationHash_, request.newCommitment);
    }

    // ──────────────────────────────────────────────
    //  Attestation verification
    // ──────────────────────────────────────────────

    /// @notice Verifies an attestation's validity: credential group and app are active,
    ///         registry address matches, attestation is not expired, and signature is from
    ///         a trusted verifier.
    /// @param attestation_ The attestation to verify.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @return signer The recovered signer address.
    function verifyAttestation(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s)
        public
        view
        returns (address signer, bytes32 registrationHash)
    {
        require(
            credentialGroups[attestation_.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "BID::credential group inactive"
        );
        require(apps[attestation_.appId].status == AppStatus.ACTIVE, "BID::app not active");
        require(attestation_.registry == address(this), "BID::wrong registry address");
        require(block.timestamp <= attestation_.issuedAt + attestationValidityDuration, "BID::attestation expired");

        signer = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().recover(v, r, s);
        require(trustedVerifiers[signer], "BID::untrusted verifier");

        uint256 familyId = credentialGroups[attestation_.credentialGroupId].familyId;
        registrationHash =
            _registrationHash(familyId, attestation_.credentialGroupId, attestation_.credentialId, attestation_.appId);
    }

    // ──────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────

    /// @dev Computes the registration hash. For family groups, uses familyId (shared across the
    ///      family) to naturally prevent double registration. For standalone groups, uses credentialGroupId.
    ///      The two-slot encoding (familyId, credentialGroupId) prevents collisions:
    ///      family hashes always have slot2=0, standalone hashes always have slot1=0.
    function _registrationHash(uint256 familyId_, uint256 credentialGroupId_, bytes32 credentialId_, uint256 appId_)
        internal
        view
        returns (bytes32)
    {
        if (familyId_ > 0) {
            return keccak256(abi.encode(address(this), familyId_, uint256(0), credentialId_, appId_));
        }
        return keccak256(abi.encode(address(this), uint256(0), credentialGroupId_, credentialId_, appId_));
    }

    /// @dev Ensures a Semaphore group exists for the (credentialGroupId, appId) pair.
    ///      Creates one lazily if it doesn't exist yet.
    /// @return semaphoreGroupId The Semaphore group ID for the pair.
    function _ensureAppSemaphoreGroup(uint256 credentialGroupId_, uint256 appId_)
        internal
        returns (uint256 semaphoreGroupId)
    {
        if (!appSemaphoreGroupCreated[credentialGroupId_][appId_]) {
            semaphoreGroupId = SEMAPHORE.createGroup();
            appSemaphoreGroups[credentialGroupId_][appId_] = semaphoreGroupId;
            appSemaphoreGroupCreated[credentialGroupId_][appId_] = true;
            emit AppSemaphoreGroupCreated(credentialGroupId_, appId_, semaphoreGroupId);
        } else {
            semaphoreGroupId = appSemaphoreGroups[credentialGroupId_][appId_];
        }
    }
}
