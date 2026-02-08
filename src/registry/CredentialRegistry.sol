// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {INullifierVerifier} from "./INullifierVerifier.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

/// @title CredentialRegistry
/// @notice Main contract for the BringID privacy-preserving credential system.
///
/// Users join credential groups via verifier-signed attestations, then prove membership
/// using Semaphore zero-knowledge proofs. Each credential group carries a score;
/// the `score()` function aggregates scores across multiple credential proofs.
///
/// App-specific identities: each app derives a unique Semaphore commitment from the
/// user's secret base + app ID. The NullifierVerifier (Noir circuit) proves the
/// Semaphore nullifier was correctly derived for that app, preventing cross-app
/// proof replay.
///
/// Two ZK proofs are validated per credential proof:
///   1. Semaphore proof — proves group membership without revealing identity
///   2. Nullifier proof (via NullifierVerifier) — proves the nullifier is correctly
///      bound to the app, and tracks nullifier uniqueness
contract CredentialRegistry is ICredentialRegistry, Ownable2Step {
    using ECDSA for bytes32;

    /// @notice The Semaphore contract used for group management and ZK proof verification.
    ISemaphore public immutable SEMAPHORE;

    /// @notice Registry of trusted verifiers that can sign attestations.
    /// Each verifier is an ECDSA signer whose signatures are accepted for
    /// credential attestations. Supports multiple verification methods
    /// (TLSN, OAuth, zkPassport, etc.).
    mapping(address => bool) public trustedVerifiers;

    /// @notice Address of the NullifierVerifier contract (Noir HonkVerifier wrapper).
    /// Verifies the nullifier proof that the Semaphore nullifier was correctly derived
    /// for the app, and tracks used nullifiers to prevent double-spending.
    address public nullifierVerifier;

    /// @notice Registry of credential groups. Each group has a score, a backing
    /// Semaphore group ID, and a status (UNDEFINED / ACTIVE / SUSPENDED).
    mapping(uint256 credentialGroupId => CredentialGroup) public credentialGroups;

    /// @notice Registry of apps. Each app has a status (UNDEFINED / ACTIVE / SUSPENDED).
    /// Apps must be registered before users can join groups or submit proofs for them.
    mapping(uint256 appId => App) public apps;

    /// @notice Tracks registered credentials to prevent duplicate group joins.
    /// Key = keccak256(registry, credentialGroupId, credentialId), which ensures
    /// one credential per (credential group, app-specific credential identity) pair
    /// while allowing different Semaphore commitments across groups.
    mapping(bytes32 => bool) public credentialRegistered;

    /// @param semaphore_ Address of the deployed Semaphore contract.
    /// @param trustedVerifier_ Address of the initial trusted verifier to add.
    /// @param nullifierVerifier_ Address of the NullifierVerifier contract.
    constructor(ISemaphore semaphore_, address trustedVerifier_, address nullifierVerifier_) {
        require(trustedVerifier_ != address(0), "Invalid trusted verifier address");
        require(nullifierVerifier_ != address(0), "Invalid nullifier verifier address");
        SEMAPHORE = semaphore_;
        trustedVerifiers[trustedVerifier_] = true;
        nullifierVerifier = nullifierVerifier_;
    }

    // ──────────────────────────────────────────────
    //  View helpers
    // ──────────────────────────────────────────────

    /// @notice Returns true if the credential group is currently active.
    /// @param credentialGroupId_ The credential group ID to check.
    function credentialGroupIsActive(uint256 credentialGroupId_) public view returns (bool) {
        return credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE;
    }

    /// @notice Returns the score assigned to a credential group.
    /// @param credentialGroupId_ The credential group ID to query.
    function credentialGroupScore(uint256 credentialGroupId_) public view returns (uint256) {
        return credentialGroups[credentialGroupId_].score;
    }

    /// @notice Returns true if the app is currently active.
    /// @param appId_ The app ID to check.
    function appIsActive(uint256 appId_) public view returns (bool) {
        return apps[appId_].status == AppStatus.ACTIVE;
    }

    // ──────────────────────────────────────────────
    //  Group membership
    // ──────────────────────────────────────────────

    /// @notice Join a credential group using a verifier-signed attestation (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main joinGroup implementation.
    ///      The signature can be reused across all networks since it signs the attestation
    ///      struct which includes the registry address.
    /// @param attestation_ The attestation containing credential details and Semaphore commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function joinGroup(Attestation memory attestation_, bytes memory signature_) public {
        require(signature_.length == 65, "Bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        joinGroup(attestation_, v, r, s);
    }

    /// @notice Join a credential group using a verifier-signed attestation.
    /// @dev Validates the attestation and adds the user's Semaphore commitment to the
    ///      backing Semaphore group. The flow:
    ///      1. Compute registration hash from (registry, credentialGroupId, credentialId) — excludes
    ///         the Semaphore commitment so the same user (credentialId) cannot join the same
    ///         group twice, even with different commitments.
    ///      2. Verify the credential group and app are active.
    ///      3. Verify the attestation was signed by a trusted verifier.
    ///      4. Mark the credential as registered and add the commitment to the Semaphore group.
    /// @param attestation_ The attestation struct containing:
    ///        - registry: must match this contract's address
    ///        - credentialGroupId: the group to join
    ///        - appId: the app this identity belongs to (must be active)
    ///        - credentialId: app-specific credential identity (used for dedup)
    ///        - semaphoreIdentityCommitment: the Semaphore identity commitment to register
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function joinGroup(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s) public {
        CredentialGroup memory _credentialGroup = credentialGroups[attestation_.credentialGroupId];
        bytes32 registrationHash =
            keccak256(abi.encode(attestation_.registry, attestation_.credentialGroupId, attestation_.credentialId));

        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(apps[attestation_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(attestation_.registry == address(this), "Wrong attestation message");
        require(!credentialRegistered[registrationHash], "Credential already registered");

        (address signer,) = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().tryRecover(v, r, s);

        require(trustedVerifiers[signer], "Untrusted verifier");

        credentialRegistered[registrationHash] = true;
        SEMAPHORE.addMember(_credentialGroup.semaphoreGroupId, attestation_.semaphoreIdentityCommitment);
        emit CredentialAdded(
            attestation_.credentialGroupId, attestation_.appId, attestation_.semaphoreIdentityCommitment
        );
    }

    // ──────────────────────────────────────────────
    //  Proof validation
    // ──────────────────────────────────────────────

    /// @notice Validates a credential group proof consisting of a Semaphore ZK proof
    ///         and a nullifier proof.
    /// @dev The validation flow:
    ///      1. Check the credential group and app are active.
    ///      2. Verify scope binding: scope must equal keccak256(msg.sender, context_),
    ///         which ties the proof to the caller and prevents replay across addresses.
    ///      3. Validate the Semaphore proof on-chain (proves group membership).
    ///         Semaphore also enforces per-group nullifier uniqueness internally.
    ///      4. Call NullifierVerifier.verifyProof() which:
    ///         - Verifies the Noir circuit proof that the nullifier was correctly derived
    ///           from (secret_base + appId), binding the proof to the correct app identity
    ///         - Tracks the nullifier as used globally, preventing double-spending
    ///         - Reverts if the nullifier was already used or the proof is invalid
    /// @param context_ Application-defined context value. Combined with msg.sender to
    ///        compute the expected scope, allowing the same user to generate distinct
    ///        proofs for different contexts.
    /// @param proof_ The credential group proof containing:
    ///        - credentialGroupId: which group is being proven
    ///        - appId: which app identity was used (must be active)
    ///        - nullifierProof: serialized Noir/UltraHonk proof for nullifier correctness
    ///        - semaphoreProof: the Semaphore ZK proof (membership + nullifier)
    function validateProof(uint256 context_, CredentialGroupProof memory proof_) public {
        CredentialGroup memory _credentialGroup = credentialGroups[proof_.credentialGroupId];
        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(apps[proof_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))), "Wrong scope");

        SEMAPHORE.validateProof(_credentialGroup.semaphoreGroupId, proof_.semaphoreProof);

        uint256 semaphoreNullifier = proof_.semaphoreProof.nullifier;
        INullifierVerifier(nullifierVerifier)
            .verifyProof(bytes32(semaphoreNullifier), proof_.appId, proof_.semaphoreProof.scope, proof_.nullifierProof);

        emit ProofValidated(proof_.credentialGroupId, proof_.appId, semaphoreNullifier);
    }

    /// @notice Validates multiple credential group proofs and returns the sum of their scores.
    /// @dev Iterates over each proof, accumulates the group's score, and calls validateProof()
    ///      which performs full Semaphore + nullifier verification. If any proof is invalid,
    ///      the entire transaction reverts.
    /// @param context_ Application-defined context value (see validateProof).
    /// @param proofs_ Array of credential group proofs to validate.
    /// @return _score The total score across all validated credential groups.
    function score(uint256 context_, CredentialGroupProof[] calldata proofs_) public returns (uint256 _score) {
        _score = 0;
        CredentialGroupProof memory _proof;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _proof = proofs_[i];
            _score += credentialGroups[_proof.credentialGroupId].score;
            validateProof(context_, _proof);
        }
    }

    // ──────────────────────────────────────────────
    //  Owner-only administration
    // ──────────────────────────────────────────────

    /// @notice Creates a new credential group with the given ID and score.
    /// @dev Also creates a corresponding Semaphore group on-chain.
    ///      The credential group ID is user-defined (not auto-incremented) and must be > 0.
    ///      Once created, a group starts as ACTIVE and can later be suspended.
    /// @param credentialGroupId_ The unique identifier for this credential group (must be > 0).
    /// @param score_ The score value assigned to this group (0 is allowed).
    function createCredentialGroup(uint256 credentialGroupId_, uint256 score_) public onlyOwner {
        require(credentialGroupId_ > 0, "Credential group ID cannot equal zero");
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED, "Credential group exists"
        );
        CredentialGroup memory _credentialGroup =
            CredentialGroup(score_, SEMAPHORE.createGroup(), ICredentialRegistry.CredentialGroupStatus.ACTIVE);
        credentialGroups[credentialGroupId_] = _credentialGroup;
        emit CredentialGroupCreated(credentialGroupId_, _credentialGroup);
    }

    /// @notice Suspends an active credential group, preventing new joins and proof validations.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE,
            "Credential group is not active"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
    }

    /// @notice Registers a new app, enabling users to join groups and submit proofs for it.
    /// @dev App IDs are user-defined (not auto-incremented) and must be > 0.
    ///      Each app represents a consuming application that derives unique Semaphore
    ///      identities from users' secret bases.
    /// @param appId_ The unique identifier for this app (must be > 0).
    function registerApp(uint256 appId_) public onlyOwner {
        require(appId_ > 0, "App ID cannot equal zero");
        require(apps[appId_].status == AppStatus.UNDEFINED, "App already exists");
        apps[appId_] = App(AppStatus.ACTIVE);
        emit AppRegistered(appId_);
    }

    /// @notice Suspends an active app, preventing new joins and proof validations for it.
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

    /// @notice Updates the NullifierVerifier contract address used for nullifier proof verification.
    /// @param nullifierVerifier_ The new NullifierVerifier address (must not be zero).
    function setNullifierVerifier(address nullifierVerifier_) public onlyOwner {
        require(nullifierVerifier_ != address(0), "Invalid nullifier verifier address");
        nullifierVerifier = nullifierVerifier_;
        emit NullifierVerifierSet(nullifierVerifier_);
    }
}
