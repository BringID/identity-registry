// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "../Errors.sol";
import {RegistryStorage} from "./RegistryStorage.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @title AttestationVerifier
/// @notice Verifies attestation signatures and common checks (active group/app, registry address,
///         expiry, trusted verifier ECDSA signature). Used by CredentialManager and RecoveryManager.
abstract contract AttestationVerifier is RegistryStorage {
    using ECDSA for bytes32;

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
        if (credentialGroups[attestation_.credentialGroupId].status != CredentialGroupStatus.ACTIVE) {
            revert CredentialGroupInactive();
        }
        if (apps[attestation_.appId].status != AppStatus.ACTIVE) revert AppNotActive();
        if (attestation_.registry != address(this)) revert WrongRegistryAddress();
        if (attestation_.chainId != block.chainid) revert WrongChain();
        if (attestation_.issuedAt > block.timestamp) revert FutureAttestation();
        if (block.timestamp > attestation_.issuedAt + attestationValidityDuration) revert AttestationExpired();

        signer = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().recover(v, r, s);
        if (!trustedVerifiers[signer]) revert UntrustedVerifier();

        uint256 familyId = credentialGroups[attestation_.credentialGroupId].familyId;
        registrationHash =
            _registrationHash(familyId, attestation_.credentialGroupId, attestation_.credentialId, attestation_.appId);
    }
}
