// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {IScorer} from "./IScorer.sol";
import {DefaultScorer} from "./DefaultScorer.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

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
contract CredentialRegistry is ICredentialRegistry, Ownable2Step {
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

    /// @notice Tracks registered credentials to prevent duplicate registrations.
    /// Key = keccak256(registry, credentialGroupId, credentialId, appId), which ensures
    /// one credential per (credential group, app, credential identity) tuple.
    mapping(bytes32 => bool) public credentialRegistered;

    /// @notice Maps registration hash to the Semaphore identity commitment that was registered.
    /// Used during recovery to look up the old commitment for removal from the Semaphore group.
    mapping(bytes32 registrationHash => uint256) public registeredCommitments;

    /// @notice Maps registration hash to the timestamp at which the credential expires.
    /// 0 means no expiry (credential lives forever).
    mapping(bytes32 registrationHash => uint256) public credentialExpiresAt;

    /// @notice Maps registration hash to a pending recovery request.
    /// A non-zero executeAfter indicates an active pending recovery.
    mapping(bytes32 registrationHash => RecoveryRequest) public pendingRecoveries;

    /// @notice Array of all registered credential group IDs (for enumeration).
    uint256[] public credentialGroupIds;

    /// @notice Auto-incrementing app ID counter. Next app will get this ID.
    uint256 public nextAppId = 1;

    /// @notice Address of the DefaultScorer contract deployed by the constructor.
    address public defaultScorer;

    /// @param semaphore_ Address of the deployed Semaphore contract.
    /// @param trustedVerifier_ Address of the initial trusted verifier to add.
    constructor(ISemaphore semaphore_, address trustedVerifier_) {
        require(trustedVerifier_ != address(0), "Invalid trusted verifier address");
        SEMAPHORE = semaphore_;
        trustedVerifiers[trustedVerifier_] = true;

        DefaultScorer _scorer = new DefaultScorer();
        _scorer.transferOwnership(msg.sender);
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
        require(signature_.length == 65, "Bad signature length");
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
        require(
            credentialGroups[attestation_.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "Credential group is inactive"
        );
        require(apps[attestation_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(attestation_.registry == address(this), "Wrong attestation message");

        bytes32 registrationHash = keccak256(
            abi.encode(
                attestation_.registry, attestation_.credentialGroupId, attestation_.credentialId, attestation_.appId
            )
        );
        require(!credentialRegistered[registrationHash], "Credential already registered");

        // Enforce same identity commitment on re-registration after expiry.
        // registeredCommitments survives removeExpiredCredential to prevent double-spend.
        uint256 previousCommitment = registeredCommitments[registrationHash];
        if (previousCommitment != 0) {
            require(attestation_.semaphoreIdentityCommitment == previousCommitment, "Must use same commitment");
        }

        (address signer,) = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().tryRecover(v, r, s);
        require(trustedVerifiers[signer], "Untrusted verifier");

        // Lazily create the per-app Semaphore group
        uint256 semaphoreGroupId = _ensureAppSemaphoreGroup(attestation_.credentialGroupId, attestation_.appId);

        credentialRegistered[registrationHash] = true;
        registeredCommitments[registrationHash] = attestation_.semaphoreIdentityCommitment;
        SEMAPHORE.addMember(semaphoreGroupId, attestation_.semaphoreIdentityCommitment);

        uint256 validityDuration = credentialGroups[attestation_.credentialGroupId].validityDuration;
        if (validityDuration > 0) {
            credentialExpiresAt[registrationHash] = block.timestamp + validityDuration;
        }

        emit CredentialRegistered(
            attestation_.credentialGroupId,
            attestation_.appId,
            attestation_.semaphoreIdentityCommitment,
            attestation_.credentialId,
            registrationHash,
            signer
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
    function submitProof(uint256 context_, CredentialGroupProof memory proof_) public {
        require(
            credentialGroups[proof_.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "Credential group is inactive"
        );
        require(apps[proof_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))), "Wrong scope");
        require(
            appSemaphoreGroupCreated[proof_.credentialGroupId][proof_.appId],
            "No Semaphore group for this credential group and app"
        );

        uint256 semaphoreGroupId = appSemaphoreGroups[proof_.credentialGroupId][proof_.appId];
        SEMAPHORE.validateProof(semaphoreGroupId, proof_.semaphoreProof);

        emit ProofValidated(proof_.credentialGroupId, proof_.appId, proof_.semaphoreProof.nullifier);
    }

    /// @notice Submits multiple credential group proofs (consuming nullifiers) and returns
    ///         the sum of their scores.
    /// @dev Iterates over each proof, accumulates the group's score, and calls submitProof()
    ///      which performs full Semaphore verification and consumes nullifiers. If any proof
    ///      is invalid, the entire transaction reverts.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to submit.
    /// @return _score The total score across all validated credential groups.
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs_) public returns (uint256 _score) {
        _score = 0;
        CredentialGroupProof memory _proof;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _proof = proofs_[i];
            _score += IScorer(apps[_proof.appId].scorer).getScore(_proof.credentialGroupId);
            submitProof(context_, _proof);
        }
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
            require(verifyProof(context_, _proof), "Invalid proof");
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
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_) public onlyOwner {
        require(credentialGroupId_ > 0, "Credential group ID cannot equal zero");
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED, "Credential group exists"
        );
        CredentialGroup memory _credentialGroup =
            CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE, validityDuration_);
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
            "Credential group does not exist"
        );
        credentialGroups[credentialGroupId_].validityDuration = validityDuration_;
        emit CredentialGroupValidityDurationSet(credentialGroupId_, validityDuration_);
    }

    /// @notice Suspends an active credential group, preventing new registrations and proof validations.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE,
            "Credential group is not active"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
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
    /// @param appId_ The app ID to suspend.
    function suspendApp(uint256 appId_) public onlyOwner {
        require(apps[appId_].status == AppStatus.ACTIVE, "App is not active");
        apps[appId_].status = AppStatus.SUSPENDED;
        emit AppSuspended(appId_);
    }

    /// @notice Adds a trusted verifier that can sign attestations.
    /// @param verifier_ The verifier address to trust (must not be zero).
    function addTrustedVerifier(address verifier_) public onlyOwner {
        require(verifier_ != address(0), "Invalid verifier address");
        trustedVerifiers[verifier_] = true;
        emit TrustedVerifierAdded(verifier_);
    }

    /// @notice Removes a trusted verifier, revoking its ability to sign attestations.
    /// @param verifier_ The verifier address to remove (must be currently trusted).
    function removeTrustedVerifier(address verifier_) public onlyOwner {
        require(trustedVerifiers[verifier_], "Verifier is not trusted");
        trustedVerifiers[verifier_] = false;
        emit TrustedVerifierRemoved(verifier_);
    }

    /// @notice Sets the recovery timelock duration for an app.
    /// @dev Only callable by the app admin. Set to 0 to disable recovery.
    /// @param appId_ The app ID to configure.
    /// @param recoveryTimelock_ The timelock duration in seconds (0 to disable recovery).
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) public {
        require(apps[appId_].admin == msg.sender, "Not app admin");
        require(apps[appId_].status == AppStatus.ACTIVE, "App is not active");
        apps[appId_].recoveryTimelock = recoveryTimelock_;
        emit AppRecoveryTimelockSet(appId_, recoveryTimelock_);
    }

    /// @notice Transfers app admin to a new address.
    /// @param appId_ The app ID.
    /// @param newAdmin_ The new admin address.
    function setAppAdmin(uint256 appId_, address newAdmin_) public {
        require(apps[appId_].admin == msg.sender, "Not app admin");
        address oldAdmin = apps[appId_].admin;
        apps[appId_].admin = newAdmin_;
        emit AppAdminTransferred(appId_, oldAdmin, newAdmin_);
    }

    /// @notice Sets a custom scorer contract for an app.
    /// @param appId_ The app ID.
    /// @param scorer_ The scorer contract address.
    function setAppScorer(uint256 appId_, address scorer_) public {
        require(apps[appId_].admin == msg.sender, "Not app admin");
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
        bytes32 registrationHash = keccak256(abi.encode(address(this), credentialGroupId_, credentialId_, appId_));
        require(credentialRegistered[registrationHash], "Credential not registered");
        require(credentialExpiresAt[registrationHash] > 0, "Credential has no expiry");
        require(block.timestamp >= credentialExpiresAt[registrationHash], "Credential not yet expired");

        uint256 commitment = registeredCommitments[registrationHash];
        uint256 semaphoreGroupId = appSemaphoreGroups[credentialGroupId_][appId_];
        SEMAPHORE.removeMember(semaphoreGroupId, commitment, merkleProofSiblings_);

        delete credentialRegistered[registrationHash];
        // NOTE: registeredCommitments is intentionally NOT deleted.
        // This forces re-registration to use the same identity commitment,
        // preserving Semaphore nullifier continuity and preventing double-spend.
        delete credentialExpiresAt[registrationHash];
        delete pendingRecoveries[registrationHash];

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
        require(signature_.length == 65, "Bad signature length");
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
        bytes32 registrationHash = keccak256(
            abi.encode(
                attestation_.registry, attestation_.credentialGroupId, attestation_.credentialId, attestation_.appId
            )
        );

        require(
            credentialGroups[attestation_.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "Credential group is inactive"
        );
        require(apps[attestation_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(attestation_.registry == address(this), "Wrong attestation message");
        require(credentialRegistered[registrationHash], "Credential not registered");
        require(pendingRecoveries[registrationHash].executeAfter == 0, "Recovery already pending");
        require(apps[attestation_.appId].recoveryTimelock > 0, "Recovery not enabled for app");

        {
            (address signer,) = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().tryRecover(v, r, s);
            require(trustedVerifiers[signer], "Untrusted verifier");
        }

        _executeInitiateRecovery(attestation_, registrationHash, merkleProofSiblings_);
    }

    function _executeInitiateRecovery(
        Attestation memory attestation_,
        bytes32 registrationHash,
        uint256[] calldata merkleProofSiblings_
    ) internal {
        uint256 oldCommitment = registeredCommitments[registrationHash];
        uint256 semaphoreGroupId = appSemaphoreGroups[attestation_.credentialGroupId][attestation_.appId];
        SEMAPHORE.removeMember(semaphoreGroupId, oldCommitment, merkleProofSiblings_);

        uint256 executeAfter = block.timestamp + apps[attestation_.appId].recoveryTimelock;
        pendingRecoveries[registrationHash] = RecoveryRequest({
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
        RecoveryRequest memory request = pendingRecoveries[registrationHash_];
        require(request.executeAfter != 0, "No pending recovery");
        require(block.timestamp >= request.executeAfter, "Recovery timelock not expired");

        require(
            credentialGroups[request.credentialGroupId].status == CredentialGroupStatus.ACTIVE,
            "Credential group is inactive"
        );
        require(apps[request.appId].status == AppStatus.ACTIVE, "App is not active");

        uint256 semaphoreGroupId = appSemaphoreGroups[request.credentialGroupId][request.appId];
        SEMAPHORE.addMember(semaphoreGroupId, request.newCommitment);
        registeredCommitments[registrationHash_] = request.newCommitment;
        delete pendingRecoveries[registrationHash_];

        emit RecoveryExecuted(registrationHash_, request.newCommitment);
    }

    // ──────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────

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
