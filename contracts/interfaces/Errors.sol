// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

// ──────────────────────────────────────────────
//  Constructor / setup
// ──────────────────────────────────────────────

error InvalidTrustedVerifier();
error ZeroMerkleTreeDuration();

// ──────────────────────────────────────────────
//  Attestation verification
// ──────────────────────────────────────────────

error InvalidAttestationSigLength();
error CredentialGroupInactive();
error AppNotActive();
error WrongRegistryAddress();
error WrongChain();
error FutureAttestation();
error AttestationExpired();
error UntrustedVerifier();

// ──────────────────────────────────────────────
//  Credential registration & renewal
// ──────────────────────────────────────────────

error AlreadyRegistered();
error InvalidCommitment();
error NotRegistered();
error CommitmentMismatch();
error RecoveryPending();
error GroupMismatch();

// ──────────────────────────────────────────────
//  Credential expiry
// ──────────────────────────────────────────────

error AlreadyExpired();
error NoExpirySet();
error NotYetExpired();

// ──────────────────────────────────────────────
//  Recovery
// ──────────────────────────────────────────────

error RecoveryAlreadyPending();
error RecoveryDisabled();
error NoPendingRecovery();
error RecoveryTimelockNotExpired();

// ──────────────────────────────────────────────
//  Proof verification
// ──────────────────────────────────────────────

error ScopeMismatch();
error NoSemaphoreGroup();
error InvalidProof();
error DuplicateCredentialGroup();

// ──────────────────────────────────────────────
//  Registry admin
// ──────────────────────────────────────────────

error ZeroCredentialGroupId();
error CredentialGroupExists();
error CredentialGroupNotFound();
error ZeroDuration();
error CredentialGroupNotActive();
error CredentialGroupNotSuspended();
error InvalidVerifierAddress();
error VerifierNotTrusted();
error InvalidScorerAddress();

// ──────────────────────────────────────────────
//  App management
// ──────────────────────────────────────────────

error NotAppAdmin();
error AppNotSuspended();
error InvalidAdminAddress();
error NotPendingAdmin();
error InvalidScorerContract();
