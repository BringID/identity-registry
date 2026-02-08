// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";

event CredentialGroupCreated(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup);
event CredentialRegistered(
    uint256 indexed credentialGroupId,
    uint256 indexed appId,
    uint256 indexed commitment,
    bytes32 credentialId,
    bytes32 registrationHash,
    address verifier
);
event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);

event TrustedVerifierAdded(address indexed verifier);
event TrustedVerifierRemoved(address indexed verifier);
event NullifierVerifierSet(address indexed verifier);

event AppRegistered(uint256 indexed appId);
event AppSuspended(uint256 indexed appId);
