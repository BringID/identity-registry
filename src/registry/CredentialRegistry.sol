// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Events.sol";
import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {IVerifier} from "./IVerifier.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

contract CredentialRegistry is ICredentialRegistry, Ownable2Step {
    using ECDSA for bytes32;

    ISemaphore public immutable SEMAPHORE;
    address public TLSNVerifier;
    address public nullifierVerifier;
    mapping(uint256 credentialGroupId => CredentialGroup) public credentialGroups;
    mapping(uint256 appId => App) public apps;
    mapping(bytes32 nonce => bool isConsumed) public nonceUsed;

    constructor(ISemaphore semaphore_, address TLSNVerifier_, address nullifierVerifier_) {
        require(TLSNVerifier_ != address(0), "Invalid TLSN Verifier address");
        require(nullifierVerifier_ != address(0), "Invalid nullifier verifier address");
        SEMAPHORE = semaphore_;
        TLSNVerifier = TLSNVerifier_;
        nullifierVerifier = nullifierVerifier_;
    }

    function credentialGroupIsActive(uint256 credentialGroupId_) public view returns (bool) {
        return credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE;
    }

    function credentialGroupScore(uint256 credentialGroupId_) public view returns (uint256) {
        return credentialGroups[credentialGroupId_].score;
    }

    function appIsActive(uint256 appId_) public view returns (bool) {
        return apps[appId_].status == AppStatus.ACTIVE;
    }

    // @notice signature can be reused across all networks
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

    function joinGroup(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s) public {
        CredentialGroup memory _credentialGroup = credentialGroups[attestation_.credentialGroupId];
        // excludes semaphoreIdentityCommitment ensuring one credential for credentialGroupId + blindedId (app-specific user ID).
        bytes32 nonce =
            keccak256(abi.encode(attestation_.registry, attestation_.credentialGroupId, attestation_.blindedId));

        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(apps[attestation_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(attestation_.registry == address(this), "Wrong attestation message");
        require(!nonceUsed[nonce], "Nonce is used");

        (address signer,) = keccak256(abi.encode(attestation_)).toEthSignedMessageHash().tryRecover(v, r, s);

        require(signer == TLSNVerifier, "Invalid TLSN Verifier signature");

        nonceUsed[nonce] = true;
        SEMAPHORE.addMember(_credentialGroup.semaphoreGroupId, attestation_.semaphoreIdentityCommitment);
        emit CredentialAdded(
            attestation_.credentialGroupId, attestation_.appId, attestation_.semaphoreIdentityCommitment
        );
    }

    // @notice Validates Semaphore proof and BringID nullifier proof
    // @dev `context_` parameter here is concatenated with sender address
    function validateProof(uint256 context_, CredentialGroupProof memory proof_) public {
        CredentialGroup memory _credentialGroup = credentialGroups[proof_.credentialGroupId];
        require(_credentialGroup.status == CredentialGroupStatus.ACTIVE, "Credential group is inactive");
        require(apps[proof_.appId].status == AppStatus.ACTIVE, "App is not active");
        require(proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))), "Wrong scope");

        SEMAPHORE.validateProof(_credentialGroup.semaphoreGroupId, proof_.semaphoreProof);

        uint256 semaphoreNullifier = proof_.semaphoreProof.nullifier;
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = bytes32(proof_.appId);
        publicInputs[1] = bytes32(proof_.semaphoreProof.scope);
        publicInputs[2] = bytes32(semaphoreNullifier);
        require(
            IVerifier(nullifierVerifier).verify(proof_.bringIdProof, publicInputs), "BringID proof verification failed"
        );

        emit ProofValidated(proof_.credentialGroupId, proof_.appId, semaphoreNullifier);
    }

    function score(uint256 context_, CredentialGroupProof[] calldata proofs_) public returns (uint256 _score) {
        _score = 0;
        CredentialGroupProof memory _proof;
        for (uint256 i = 0; i < proofs_.length; i++) {
            _proof = proofs_[i];
            _score += credentialGroups[_proof.credentialGroupId].score;
            validateProof(context_, _proof);
        }
    }

    // ONLY OWNER //

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

    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE,
            "Credential group is not active"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
    }

    function registerApp(uint256 appId_) public onlyOwner {
        require(appId_ > 0, "App ID cannot equal zero");
        require(apps[appId_].status == AppStatus.UNDEFINED, "App already exists");
        apps[appId_] = App(AppStatus.ACTIVE);
        emit AppRegistered(appId_);
    }

    function suspendApp(uint256 appId_) public onlyOwner {
        require(apps[appId_].status == AppStatus.ACTIVE, "App is not active");
        apps[appId_].status = AppStatus.SUSPENDED;
        emit AppSuspended(appId_);
    }

    function setVerifier(address TLSNVerifier_) public onlyOwner {
        require(TLSNVerifier_ != address(0), "Invalid TLSN Verifier address");
        TLSNVerifier = TLSNVerifier_;
        emit TLSNVerifierSet(TLSNVerifier_);
    }

    function setNullifierVerifier(address nullifierVerifier_) public onlyOwner {
        require(nullifierVerifier_ != address(0), "Invalid nullifier verifier address");
        nullifierVerifier = nullifierVerifier_;
        emit NullifierVerifierSet(nullifierVerifier_);
    }
}
