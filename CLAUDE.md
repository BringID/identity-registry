# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BringID Identity Registry — Solidity smart contracts for a privacy-preserving credential system. Users register credentials via verifier-signed attestations, then prove membership using Semaphore zero-knowledge proofs. Each credential group carries a score; `submitProofs()` validates proofs (consuming nullifiers) and returns the aggregate score.

Target chain: Base (chain ID 84532). Built with Foundry and Solidity ^0.8.23.

## Build & Test Commands

```bash
make install              # Install dependencies (yarn)
forge build               # Compile contracts
forge fmt --check         # Check formatting (CI enforces this)
forge fmt                 # Auto-format
make test                 # Run tests (forge test --summary)
make test-all             # Run all tests with --via-ir --ffi
make test-registry        # CredentialRegistry tests only (requires --ffi)
```

Run a single test function:
```bash
forge test --match-test "testFunctionName" -v
```

Run a single test file:
```bash
forge test --match-path "test/CredentialRegistry.t.sol" --ffi -v
```

Tests that use Semaphore proof generation require `--ffi` flag (they shell out to Node.js scripts in `test/semaphore-js/`).

## Deployment

Requires `PRIVATE_KEY` and `SEMAPHORE_ADDRESS` env vars. Remote deploys also need `BASE_RPC_URL`.

```bash
make deploy-local         # Local anvil (port 8545)
make deploy               # Base chain
make deploy-idcard-local  # IdCard contract locally
make deploy-idcard        # IdCard contract to Base
```

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D` |
| CredentialRegistry | `0x78Ce003ff79557A44eae862377a00F66df0557B2` |
| DefaultScorer | `0x68a3CA701c6f7737395561E000B5cCF4ECa5185A` |

Owner / trusted verifier: `0xc7308C53B6DD25180EcE79651Bf0b1Fd16e64452`
Additional trusted verifier: `0x3c50f7055D804b51e506Bc1EA7D082cB1548376C`

### Registered Apps (Base Sepolia)

| App ID | Admin | Recovery Timelock |
|--------|-------|-------------------|
| 1 | `0xc7308C53B6DD25180EcE79651Bf0b1Fd16e64452` | 0 (disabled) |

### Semaphore Identity Derivation

Deterministic Semaphore identities are derived as:
```
seed = keccak256(abi.encodePacked(walletPrivateKey, appId, credentialGroupId))
identity = new Identity(seed)
```

**Test identity** (deployer wallet, app 1, Uber Rides group 12):
- Seed: `0x92d29499f05293703d2b5a4a1b258ce13dc4a291759adf968b5e2f8cb65f98eb`
- Commitment: `5547623340946663008626844335290495993250135574086741156373042143070458722495`
- Export (base64): `MHg5MmQyOTQ5OWYwNTI5MzcwM2QyYjVhNGExYjI1OGNlMTNkYzRhMjkxNzU5YWRmOTY4YjVlMmY4Y2I2NWY5OGVi`

### Credential Groups (Base Sepolia)

| ID | Credential | Group | Family | Default Score | Validity Duration |
|----|------------|-------|--------|---------------|-------------------|
| 1 | Farcaster | Low | 1 | 2 | 30 days |
| 2 | Farcaster | Medium | 1 | 5 | 60 days |
| 3 | Farcaster | High | 1 | 10 | 90 days |
| 4 | GitHub | Low | 2 | 2 | 30 days |
| 5 | GitHub | Medium | 2 | 5 | 60 days |
| 6 | GitHub | High | 2 | 10 | 90 days |
| 7 | X (Twitter) | Low | 3 | 2 | 30 days |
| 8 | X (Twitter) | Medium | 3 | 5 | 60 days |
| 9 | X (Twitter) | High | 3 | 10 | 90 days |
| 10 | zkPassport | — | 0 | 20 | 180 days |
| 11 | Self | — | 0 | 20 | 180 days |
| 12 | Uber Rides | — | 0 | 10 | 180 days |
| 13 | Apple Subs | — | 0 | 10 | 180 days |
| 14 | Binance KYC | — | 0 | 20 | 180 days |
| 15 | OKX KYC | — | 0 | 20 | 180 days |

## Architecture

### Core contracts (`src/registry/`)

- **CredentialRegistry.sol** — Main contract. Owner creates credential groups (metadata only — status). Per-app Semaphore groups are created lazily on first credential registration for each (credentialGroup, app) pair via `appSemaphoreGroups` mapping. Credential lifecycle has three distinct operations: `registerCredential()` for first-time registration with a verifier-signed attestation; `renewCredential()` for renewing previously-registered credentials (same identity commitment, resets validity duration); and `initiateRecovery()` / `executeRecovery()` for timelocked key replacement (changes identity commitment, does NOT update validity duration). Proof API has state-changing and view variants: `submitProof()` / `submitProofs()` consume Semaphore nullifiers (binding proofs to the caller via `scope == keccak256(abi.encode(msg.sender, context))`); `verifyProof()` / `verifyProofs()` are view-only counterparts using Semaphore's `verifyProof()` that don't consume nullifiers; `getScore()` is a view that verifies proofs and returns the aggregate score. Since each app has its own Semaphore group, cross-app proof replay is naturally prevented. Supports multiple trusted verifiers (`trustedVerifiers` mapping) for different verification methods (TLSN, OAuth, zkPassport, etc.). Deploys a `DefaultScorer` in the constructor.
- **ICredentialRegistry.sol** — Interface with core data types: `CredentialGroup` (status + validityDuration + familyId), `App` (status + recoveryTimelock + admin + scorer), `RecoveryRequest` (credentialGroupId + appId + newCommitment + executeAfter), `CredentialRecord` (registered + expired + commitment + expiresAt + credentialGroupId + pendingRecovery), `Attestation` (registry + credentialGroupId + credentialId + appId + commitment + issuedAt), `CredentialGroupProof` (credentialGroupId + appId + semaphoreProof).
- **IScorer.sol** — Interface for scorer contracts: `getScore(uint256 credentialGroupId) → uint256`.
- **DefaultScorer.sol** — Default scorer owned by BringID. Stores global scores per credential group via `setScore()` / `getScore()`. Deployed automatically by the CredentialRegistry constructor.
- **Events.sol** — Event declarations.

### Key design decisions

- **Ownable2Step** (OpenZeppelin) for admin operations — two-step ownership transfer.
- **Per-app Semaphore groups**: each (credentialGroup, app) pair gets its own Semaphore group, created lazily on first registration. Since Semaphore enforces per-group nullifier uniqueness, separate groups per app naturally prevent cross-app proof replay — no second circuit needed.
- **Credential state**: per-credential state is stored in a single `credentials` mapping (`bytes32 registrationHash => CredentialRecord`). The registration hash uses a two-slot encoding to prevent collisions: for family groups (familyId > 0): `keccak256(registry, familyId, 0, credentialId, appId)` — all groups in the same family share one slot; for standalone groups (familyId == 0): `keccak256(registry, 0, credentialGroupId, credentialId, appId)`. The `credentialGroupId` is stored in `CredentialRecord` to track which specific group the credential belongs to.
- **Family enforcement**: credential groups with the same `familyId` (> 0) share a registration hash, so a user can only hold one credential per family per app (e.g. cannot have both Farcaster Low and Farcaster High). Group changes within a family go through the recovery timelock (`initiateRecovery`/`executeRecovery`) to prevent double-spend with different Semaphore nullifiers. Standalone groups (familyId = 0) have no family constraint. Family IDs: 1 = Farcaster (groups 1–3), 2 = GitHub (groups 4–6), 3 = X/Twitter (groups 7–9), 0 = standalone (groups 10–15).
- **Scope binding**: `submitProof` ties proofs to `msg.sender` + a context value, preventing proof replay across callers.
- **App-specific identities**: each app derives a unique Semaphore commitment from `keccak256(abi.encodePacked(walletPrivateKey, appId, credentialGroupId))` fed into `new Identity(seed)`. This ensures per-app and per-credential-group isolation.
- **Trusted verifiers**: multiple signers supported via `trustedVerifiers` mapping with `addTrustedVerifier`/`removeTrustedVerifier`. Supports TLSN, OAuth, zkPassport, etc.
- Semaphore groups are created on-chain via the Semaphore contract; the registry maps (credentialGroupId, appId) pairs to Semaphore group IDs via `appSemaphoreGroups`.
- **Custom app scoring**: Scores are managed by separate Scorer contracts implementing `IScorer`. A `DefaultScorer` (owned by BringID) holds global scores. Each app points to a scorer — `DefaultScorer` by default, or a custom implementation set via `setAppScorer()`. `submitProofs()` and `getScore()` call `apps[appId].scorer.getScore(credentialGroupId)` for each proof.
- **App self-registration**: Apps are registered via `registerApp(recoveryTimelock)` — public, auto-increment ID, caller becomes admin. App admins manage their own scorer (`setAppScorer`), recovery timelock (`setAppRecoveryTimelock`), admin transfer (`setAppAdmin`), suspension (`suspendApp`), and reactivation (`activateApp`).
- **Credential expiry**: per-credential-group `validityDuration` (seconds, 0 = no expiry). Set at `createCredentialGroup(id, validityDuration, familyId)` time and updatable via `setCredentialGroupValidityDuration()` (owner-only, affects future registrations/renewals only). On registration/renewal, `cred.expiresAt = block.timestamp + validityDuration` (skipped when 0). `removeExpiredCredential()` is public — anyone can call it after expiry to remove the commitment from the Semaphore group and set `cred.expired = true`. **`cred.registered` stays true and `cred.commitment` is NOT cleared** — this enforces commitment continuity on renewal and enables recovery. `cred.pendingRecovery` is cleared to avoid orphaned state. Between expiry and removal, the credential technically still works (removal must be triggered).
- **Register vs Renew separation**: `registerCredential()` is strictly for first-time registration — it rejects calls where `cred.registered` is true. `renewCredential()` handles all subsequent activations: it requires the same identity commitment and the same credential group as the original registration, re-adds the commitment to Semaphore if `cred.expired` is true, clears the expired flag, and resets the validity duration. Early renewal (before expiry) is allowed, effectively extending the credential. Group changes are NOT allowed via renewal — they must go through recovery (to prevent double-spend with different nullifiers). This prevents a **double-spend attack** where a user could change their commitment or group after expiry to obtain new Semaphore nullifiers for the same scope. Renewal is blocked during pending recovery (`require(cred.pendingRecovery.executeAfter == 0)`).
- **Attestation verification**: `verifyAttestation()` is a `public view` function that validates all common attestation checks (active credential group/app, registry address, expiry, ECDSA signature from trusted verifier) and returns the recovered signer address. Used internally by `registerCredential()`, `renewCredential()`, and `initiateRecovery()`.
- **Attestation expiry**: attestations include an `issuedAt` timestamp signed by the verifier. The contract enforces `block.timestamp <= issuedAt + attestationValidityDuration` (default 30 minutes). The owner can update the duration via `setAttestationValidityDuration()` (must be > 0).
- **Key recovery and group changes**: per-app timelocked commitment replacement. When a user loses their wallet, they re-authenticate via any supported verification flow (zkTLS, OAuth, zkPassport, zkKYC, etc.); the verifier re-derives the same `credentialId` and signs an attestation with a new commitment and the same `appId`. `initiateRecovery()` removes the old commitment from the per-app Semaphore group immediately and queues the new one behind the app's `recoveryTimelock`. `executeRecovery()` adds the new commitment after the timelock expires and updates `cred.credentialGroupId`. `initiateRecovery()` also supports group changes within the same family (e.g. upgrading from Farcaster Low to High) — the attestation can target a different group as long as both groups share the same familyId. The timelock prevents double-spend by ensuring no valid commitment exists during the transition. App admin sets `recoveryTimelock` at `registerApp()` time (0 = disabled); can toggle on/off later via `setAppRecoveryTimelock()`. The `Attestation` struct includes `appId` for timelock lookup and per-app group resolution. `cred.commitment` tracks the current commitment per registration hash; `cred.pendingRecovery` tracks in-flight recovery requests.
- **Recovery on expired+removed credentials**: `initiateRecovery()` works even after a credential has expired and been removed from the Semaphore group. It checks `cred.registered` (which stays true after expiry), so a user who lost their key after expiry can still recover. When `cred.expired` is true, `_executeInitiateRecovery()` skips the `SEMAPHORE.removeMember()` call. `executeRecovery()` clears `cred.expired` and adds the new commitment to the Semaphore group. **Recovery does NOT modify `cred.expiresAt`** — key replacement and credential validity are independent concerns.
- **Error message convention**: all `require` error strings use a `BID::` prefix (e.g. `"BID::not registered"`, `"BID::app not active"`). This makes BringID errors instantly identifiable in transaction traces and logs. Keep messages short and lowercase after the prefix.
- **Expiry + recovery guard**: `removeExpiredCredential()` rejects calls when `cred.pendingRecovery.executeAfter != 0` (`"BID::recovery pending"`), preventing a double-remove from the Semaphore group after `initiateRecovery()` has already removed the commitment.

### Scripts (`script/`)

- **Deploy.s.sol** — `DeployDev` (dev with token), `DeployToken`, `Deploy` (production). Require `SEMAPHORE_ADDRESS` env var.
- **DeployLocal.s.sol** — Deploys SemaphoreVerifier, Semaphore, and CredentialRegistry for local e2e testing.
- **CredentialGroups.s.sol** — Batch-creates credential groups and sets scores on DefaultScorer.
- **RegisterApps.s.sol** — Batch-registers apps (public, auto-increment).
- **MockSignature.s.sol** — Generates test ECDSA signatures for attestations.
- **register-credential.mjs** — E2e script: derives Semaphore identity from `keccak256(PRIVATE_KEY, appId, credentialGroupId)` via `new Identity(seed)`, signs attestation, calls `registerCredential()`. Requires `PRIVATE_KEY`, `REGISTRY_ADDRESS` env vars.
- **verify-proof.mjs** — E2e script: derives Semaphore identity the same way, generates ZK proof, calls `submitProof()`. Requires `PRIVATE_KEY`, `REGISTRY_ADDRESS`, `SEMAPHORE_ADDRESS` env vars.

### Local e2e testing

```bash
# 1. Start anvil
anvil --port 8545

# 2. Deploy (uses anvil account 0)
PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  FOUNDRY_PROFILE=ci forge script script/DeployLocal.s.sol:DeployLocal \
  --rpc-url http://127.0.0.1:8545 --broadcast

# 3. Register credential (use REGISTRY_ADDRESS from deploy output)
PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  REGISTRY_ADDRESS=<addr> \
  node script/register-credential.mjs --credential-group-id 1 --app-id 1 --create-group

# 4. Submit proof (use REGISTRY_ADDRESS and SEMAPHORE_ADDRESS from deploy output)
PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  REGISTRY_ADDRESS=<addr> SEMAPHORE_ADDRESS=<addr> \
  node script/verify-proof.mjs --credential-group-id 1 --app-id 1 --context 0
```

### Test infrastructure (`test/`)

- **CredentialRegistry.t.sol** — Comprehensive tests including Semaphore proof generation via FFI.
- **TestUtils.sol** — FFI library calling Node.js to generate Semaphore commitments and proofs.
- **test/semaphore-js/** — Node.js helpers (`commitment.mjs`, `proof.mjs`) invoked via Foundry FFI.

### Dependencies

Solidity libraries managed via git submodules (`lib/`) and npm (`node_modules/`):
- `@semaphore-protocol/contracts` — Semaphore on-chain verifier
- `openzeppelin-contracts` — Ownable2Step, ECDSA, ERC20
- `solmate` — Gas-optimized utilities
- Import remappings defined in `remappings.txt`

### CI

GitHub Actions (`.github/workflows/test.yml`). Triggered on push, PR, and manual dispatch. Steps:

1. **Install** — Foundry toolchain + `yarn install --frozen-lockfile` (for `@semaphore-protocol` and other npm deps)
2. **Format check** — `forge fmt --check`
3. **Build** — `forge build --sizes` (uses `ci` profile, `via_ir = false`)
4. **Build (via-ir, src only)** — `FOUNDRY_PROFILE=default forge build --skip test --skip script` (uses default profile, `via_ir = true`). Compiles only `src/` contracts and their imports (lightweight Semaphore interfaces). Skips test/script to avoid compiling heavy Semaphore implementation (`Semaphore.sol`, `SemaphoreVerifier.sol`, `PoseidonT3`).
5. **Upload artifacts** — Uploads via-ir compiled `CredentialRegistry.sol/` and `DefaultScorer.sol/` as GitHub Actions artifacts. Download with `gh run download <run-id> -n via-ir-contracts`.
6. **Tests** — `forge test --ffi -vvv` (uses `ci` profile, `via_ir = false`)

### Foundry config (`foundry.toml`)

- **`[profile.default]`**: `via_ir = true` — production-optimized. Used by CI via-ir build step and for deployment. Local `via_ir` compilation may OOM on machines with ≤16GB RAM.
- **`[profile.ci]`**: `via_ir = false` — fast builds for formatting, size checks, and tests. CI sets `FOUNDRY_PROFILE=ci` globally.
- Optimizer with 200 runs
- Fuzz: 10 runs, 100 max rejections
- Without `via_ir`, stack-too-deep errors are avoided by extracting helper functions (e.g. `_makeProof` in tests, `_executeInitiateRecovery` in CredentialRegistry).
