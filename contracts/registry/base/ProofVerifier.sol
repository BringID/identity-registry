// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/interfaces/Errors.sol";
import "@bringid/contracts/interfaces/Events.sol";
import {CredentialGroupProof} from "@bringid/contracts/interfaces/ICredentialRegistry.sol";
import {IScorer} from "@bringid/contracts/interfaces/IScorer.sol";
import {RegistryStorage} from "./RegistryStorage.sol";

/// @title ProofVerifier
/// @notice Handles Semaphore proof submission, verification, and score aggregation.
abstract contract ProofVerifier is RegistryStorage {
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
    ///
    ///      WARNING: The `message` field of the Semaphore proof is NOT validated by this
    ///      function. When a smart contract calls `submitProof()`, any user can copy the
    ///      proof from the mempool and front-run the original transaction through the same
    ///      contract, because `msg.sender` (and therefore `scope`) will be identical.
    ///      Smart contract callers SHOULD bind the `message` field to the intended
    ///      recipient or action to prevent this. See `BringIDGated` for a ready-made
    ///      helper that enforces message binding.
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
        whenNotPaused
        returns (uint256 _score)
    {
        _score = _submitProof(context_, proof_);
    }

    /// @notice Submits multiple credential group proofs (consuming nullifiers) and returns
    ///         the sum of their scores.
    /// @dev Iterates over each proof, accumulates the group's score, and calls _submitProof()
    ///      which performs full Semaphore verification and consumes nullifiers. If any proof
    ///      is invalid, the entire transaction reverts.
    ///
    ///      WARNING: The `message` field of each Semaphore proof is NOT validated. When a
    ///      smart contract calls `submitProofs()`, proofs can be front-run through the same
    ///      contract because `msg.sender` (and therefore `scope`) is identical for any
    ///      caller. Smart contract callers SHOULD validate `message` binding before
    ///      forwarding proofs. See `BringIDGated` for a ready-made helper.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to submit.
    /// @return _score The total score across all validated credential groups.
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs_)
        public
        nonReentrant
        whenNotPaused
        returns (uint256 _score)
    {
        _checkNoDuplicateGroups(proofs_);
        _score = 0;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _score += _submitProof(context_, proofs_[i]);
        }
    }

    /// @dev Internal implementation of submitProof. Validates the proof, consumes the
    ///      Semaphore nullifier, and returns the credential group's score from the app's scorer.
    ///      The `message` field is intentionally not checked here — it is a free-form field
    ///      that callers can use for application-specific binding (e.g. recipient address).
    function _submitProof(uint256 context_, CredentialGroupProof memory proof_) internal returns (uint256 _score) {
        if (credentialGroups[proof_.credentialGroupId].status != CredentialGroupStatus.ACTIVE) {
            revert CredentialGroupInactive();
        }
        if (apps[proof_.appId].status != AppStatus.ACTIVE) revert AppNotActive();
        if (proof_.semaphoreProof.scope != uint256(keccak256(abi.encode(msg.sender, context_)))) {
            revert ScopeMismatch();
        }
        if (!appSemaphoreGroupCreated[proof_.credentialGroupId][proof_.appId]) revert NoSemaphoreGroup();

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
        return _verifyProof(msg.sender, context_, proof_);
    }

    /// @notice Verifies multiple credential group proofs without consuming nullifiers.
    /// @dev View-only counterpart to submitProofs(). Returns false if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs_) public view returns (bool) {
        _checkNoDuplicateGroups(proofs_);
        for (uint256 i = 0; i < proofs_.length; i++) {
            if (!_verifyProof(msg.sender, context_, proofs_[i])) return false;
        }
        return true;
    }

    /// @notice Verifies multiple proofs and returns the aggregate score without consuming nullifiers.
    /// @dev View-only counterpart to submitProofs(). Reverts if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return _score The total score across all verified credential groups.
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs_) public view returns (uint256 _score) {
        _checkNoDuplicateGroups(proofs_);
        _score = 0;
        CredentialGroupProof memory _proof;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _proof = proofs_[i];
            if (!_verifyProof(msg.sender, context_, _proof)) revert InvalidProof();
            _score += IScorer(apps[_proof.appId].scorer).getScore(_proof.credentialGroupId);
        }
    }

    /// @dev Internal implementation of verifyProof. Validates the proof against the given sender
    ///      address for scope computation.
    function _verifyProof(address sender_, uint256 context_, CredentialGroupProof memory proof_)
        internal
        view
        returns (bool)
    {
        if (credentialGroups[proof_.credentialGroupId].status != CredentialGroupStatus.ACTIVE) return false;
        if (apps[proof_.appId].status != AppStatus.ACTIVE) return false;
        if (proof_.semaphoreProof.scope != uint256(keccak256(abi.encode(sender_, context_)))) return false;
        if (!appSemaphoreGroupCreated[proof_.credentialGroupId][proof_.appId]) return false;

        uint256 semaphoreGroupId = appSemaphoreGroups[proof_.credentialGroupId][proof_.appId];
        return SEMAPHORE.verifyProof(semaphoreGroupId, proof_.semaphoreProof);
    }

    /// @dev Reverts if any two proofs share the same credentialGroupId, preventing score inflation.
    function _checkNoDuplicateGroups(CredentialGroupProof[] calldata proofs_) internal pure {
        for (uint256 i = 1; i < proofs_.length; i++) {
            for (uint256 j = 0; j < i; j++) {
                if (proofs_[i].credentialGroupId == proofs_[j].credentialGroupId) {
                    revert DuplicateCredentialGroup();
                }
            }
        }
    }
}
