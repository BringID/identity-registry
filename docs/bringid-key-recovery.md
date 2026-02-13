# How BringID Recovery Solves Wallet Loss

## The Problem

- User's Semaphore identity is derived from wallet signature: `secret_base = hash(wallet_signature)`
- Wallet lost → can't produce signature → can't derive `secret_base` → can't generate proofs
- User locked out of apps using that wallet

## The Solution

- `credentialId = hash(oauth_id, app_id, verifier_private_key)` — unique per user per app, non-reversible
- On-chain storage: `registeredCommitments[registrationHash]` maps each credential registration to its current Semaphore commitment, where `registrationHash = keccak256(registry, credentialGroupId, credentialId, appId)`
- User can use **different wallets for different apps**
- Recovery is **per-app**, not global

## Why Verifier Private Key?

- Without it: attacker could rainbow table common `oauth_id`s against known `app_id`s
- With it: even with on-chain `credentialId` and known `app_id`, can't brute-force `oauth_id`
- Only the Verifier can derive `credentialId` from OAuth credentials

## Recovery Flow (Per-App)

- User re-authenticates via OAuth with a **new wallet** for a specific app
- Verifier derives the **same `credentialId`** = `hash(oauth_id, app_id, verifier_private_key)`
- Verifier signs a new `Attestation` with the same `credentialId` but a new `semaphoreIdentityCommitment`
- `initiateRecovery()`: old commitment is **immediately removed** from the per-app Semaphore group; new commitment is **queued with app-specific timelock**
- During the timelock period, the user has no valid commitment in the group (intentional — prevents use of a compromised identity)
- `executeRecovery()`: after timelock expires, new commitment is **added to group** (callable by anyone)
- User can generate valid proofs for that app with new wallet
- Other apps **unaffected** (different `credentialId`, different commitment, different Semaphore group)

## Per-App Flexibility

- App admin sets `recoveryTimelock` at `registerApp()` time (0 = disabled)
- App admin can toggle recovery on/off later via `setAppRecoveryTimelock()`
- User recovers apps **independently** as needed
- Compromise/recovery of one app doesn't affect others

## Key Insight

- `credentialId` is already app-scoped and salted with Verifier key — not reversible
- The `Attestation` struct includes `appId`, which the contract uses to look up the correct per-app Semaphore group and recovery timelock
- OAuth is the anchor; wallets are replaceable and per-app
- Verifier can always re-derive `credentialId` from OAuth + app_id + private key
