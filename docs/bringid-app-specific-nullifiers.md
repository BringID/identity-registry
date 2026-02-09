# BringID App-Specific Identity & Per-App Semaphore Groups

## Overview

BringID is a privacy-preserving credential system where:
- Users verify credentials (via TLSN, OAuth, zkPassport, etc.) once per app
- Each app gets a unique, unlinkable user identity
- Credential groups carry scores; apps aggregate scores from multiple credential proofs
- No single party can link wallet address to real-world identity

---

## Identity Model

```
secret_base       = hash(wallet_signature)
identity_secret   = hash(secret_base, app_id)
commitment        = hash(identity_secret)
nullifier         = hash(scope, identity_secret)
```

- Same wallet + same app → same identity
- Same wallet + different app → different identity
- Each user has one commitment per (credentialGroup, app) Semaphore group

---

## Identity Derivation

```
wallet_signature
       │
       ▼
   secret_base = hash(signature)
       │
       ├────────────────┬────────────────┐
       ▼                ▼                ▼
   hash(sb, app_A)  hash(sb, app_B)  hash(sb, app_C)
       │                │                │
       ▼                ▼                ▼
   identity_A       identity_B       identity_C
       │                │                │
       ▼                ▼                ▼
   commitment_A     commitment_B     commitment_C
```

Each app gets an unlinkable identity from the same wallet.

---

## Credential ID Derivation

```
credentialId = hash(oauth_id, app_id, verifier_private_key)
```

- `oauth_id` — from OAuth provider (or other credential source)
- `app_id` — public, known
- `verifier_private_key` — secret, held only by Verifier

This prevents rainbow table attacks: even with on-chain `credentialId` and known `app_id`, attacker can't brute-force `oauth_id` without the Verifier's key.

The `credentialId` is a `bytes32` field in the on-chain `Attestation` struct. It uniquely identifies a user's credential within a (credentialGroup, app) pair and is used for deduplication and key recovery.

---

## Per-App Semaphore Groups

Each (credentialGroup, app) pair gets its own Semaphore group, created lazily on first credential registration.

```
credentialGroup_1 + app_A  →  semaphoreGroup_1
credentialGroup_1 + app_B  →  semaphoreGroup_2
credentialGroup_2 + app_A  →  semaphoreGroup_3
credentialGroup_2 + app_B  →  semaphoreGroup_4
```

Since Semaphore enforces per-group nullifier uniqueness, separate groups per app naturally prevent cross-app proof replay — no second ZK circuit needed. A proof generated for App A's Semaphore group is invalid against App B's group.

---

## Proof System

Each credential proof is a standard Semaphore ZK proof against a per-app group:

- **Public inputs:** `merkleTreeDepth`, `merkleTreeRoot`, `nullifier`, `message`, `scope`
- **Private inputs:** `identity_secret`, `merkle_path`
- **Scope binding:** `scope = keccak256(caller_address, context)` — ties the proof to the on-chain caller and a context value, preventing replay across addresses

### State-changing vs view

| Function | Mutates state? | Returns |
|---|---|---|
| `submitProof(context, proof)` | Yes — consumes nullifier | — |
| `submitProofs(context, proofs)` | Yes — consumes nullifiers | aggregate score |
| `verifyProof(context, proof)` | No | bool |
| `verifyProofs(context, proofs)` | No | bool |
| `getScore(context, proofs)` | No | aggregate score |

Scoring is determined by each app's Scorer contract (`IScorer.getScore(credentialGroupId)`). A `DefaultScorer` (owned by BringID) provides global scores; apps can set custom scorers.

---

## Registration Flow

```
User                    Verifier                        Contract
 │                         │                               │
 │── credential + wallet ─▶│                               │
 │   (OAuth, TLSN, etc.)  │                               │
 │                         │── derive credentialId          │
 │                         │   derive commitment            │
 │                         │   (per app_id)                 │
 │                         │   sign Attestation             │
 │                         │                               │
 │── registerCredential(attestation, signature) ──────────▶│
 │                         │                               │── verify trusted verifier
 │                         │                               │── check deduplication
 │                         │                               │── lazily create per-app
 │                         │                               │   Semaphore group
 │                         │                               │── add commitment to group
```

The `Attestation` struct contains: `registry`, `credentialGroupId`, `credentialId`, `appId`, `semaphoreIdentityCommitment`.

Credential deduplication: `keccak256(registry, credentialGroupId, credentialId, appId)` — prevents the same user from registering a credential twice for the same app, but allows different commitments across apps.

---

## Verification Flow

```
User / Consuming App                    Contract
 │                                         │
 │── context + proof ─────────────────────▶│
 │   (credentialGroupId, appId,            │
 │    semaphoreProof)                      │
 │                                         │── check credential group active
 │                                         │── check app active
 │                                         │── verify scope == keccak256(msg.sender, context)
 │                                         │── verify Semaphore proof against per-app group
 │                                         │── (submitProof) consume nullifier
 │                                         │── (submitProofs) accumulate score
 │                                         │
 │◀── score / bool ────────────────────────│
```

---

## Credential Expiry

Credential groups can define a `validityDuration` (seconds, 0 = no expiry). When a user registers a credential in a group with a non-zero duration, `credentialExpiresAt` is set to `block.timestamp + validityDuration`. After expiry, anyone can call `removeExpiredCredential()` with the Merkle proof siblings to remove the commitment from the Semaphore group, clearing registration state and allowing re-registration with a fresh attestation.

---

## Privacy Properties

- **Unlinkable identities:** different commitment per app, derived from the same `secret_base`
- **Scope binding:** proofs are tied to `msg.sender` + context, preventing replay across callers
- **Per-app groups:** cross-app proof replay is structurally impossible (different Semaphore groups)
- **Credential deduplication:** prevents double-registration within the same app
- **Non-reversible credentialId:** salted with Verifier's private key, resistant to brute-force
