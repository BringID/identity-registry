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
| CredentialRegistry | `0x3353a67d5963C263F3c6F4dA3Fc45509981160A9` |
| DefaultScorer | `0x8AD32E9076BDe94B4b31A0b7a283fed23dFe5af4` |

Owner / trusted verifier: `0xc7308C53B6DD25180EcE79651Bf0b1Fd16e64452`

### Credential Groups (Base Sepolia)

| ID | Credential | Group | Default Score | Validity Duration |
|----|------------|-------|---------------|-------------------|
| 1 | Farcaster | Low | 2 | No expiry |
| 2 | Farcaster | Medium | 5 | No expiry |
| 3 | Farcaster | High | 10 | No expiry |
| 4 | GitHub | Low | 2 | No expiry |
| 5 | GitHub | Medium | 5 | No expiry |
| 6 | GitHub | High | 10 | No expiry |
| 7 | X (Twitter) | Low | 2 | No expiry |
| 8 | X (Twitter) | Medium | 5 | No expiry |
| 9 | X (Twitter) | High | 10 | No expiry |
| 10 | zkPassport | — | 20 | No expiry |
| 11 | Self | — | 20 | No expiry |
| 12 | Uber Rides | — | 10 | No expiry |
| 13 | Apple Subs | — | 10 | No expiry |
| 14 | Binance KYC | — | 20 | No expiry |
| 15 | OKX KYC | — | 20 | No expiry |

## Architecture

### Core contracts (`src/registry/`)

- **CredentialRegistry.sol** — Main contract. Owner creates credential groups (metadata only — status). Per-app Semaphore groups are created lazily on first credential registration for each (credentialGroup, app) pair via `appSemaphoreGroups` mapping. Credential lifecycle has three distinct operations: `registerCredential()` for first-time registration with a verifier-signed attestation; `renewCredential()` for renewing previously-registered credentials (same identity commitment, resets validity duration); and `initiateRecovery()` / `executeRecovery()` for timelocked key replacement (changes identity commitment, does NOT update validity duration). Proof API has state-changing and view variants: `submitProof()` / `submitProofs()` consume Semaphore nullifiers (binding proofs to the caller via `scope == keccak256(abi.encode(msg.sender, context))`); `verifyProof()` / `verifyProofs()` are view-only counterparts using Semaphore's `verifyProof()` that don't consume nullifiers; `getScore()` is a view that verifies proofs and returns the aggregate score. Since each app has its own Semaphore group, cross-app proof replay is naturally prevented. Supports multiple trusted verifiers (`trustedVerifiers` mapping) for different verification methods (TLSN, OAuth, zkPassport, etc.). Deploys a `DefaultScorer` in the constructor.
- **ICredentialRegistry.sol** — Interface with core data types: `CredentialGroup` (status + validityDuration), `App` (status + recoveryTimelock + admin + scorer), `RecoveryRequest` (credentialGroupId + appId + newCommitment + executeAfter), `CredentialRecord` (registered + expired + commitment + expiresAt + pendingRecovery), `Attestation` (registry + credentialGroupId + credentialId + appId + commitment + issuedAt), `CredentialGroupProof` (credentialGroupId + appId + semaphoreProof).
- **IScorer.sol** — Interface for scorer contracts: `getScore(uint256 credentialGroupId) → uint256`.
- **DefaultScorer.sol** — Default scorer owned by BringID. Stores global scores per credential group via `setScore()` / `getScore()`. Deployed automatically by the CredentialRegistry constructor.
- **Events.sol** — Event declarations.

### Key design decisions

- **Ownable2Step** (OpenZeppelin) for admin operations — two-step ownership transfer.
- **Per-app Semaphore groups**: each (credentialGroup, app) pair gets its own Semaphore group, created lazily on first registration. Since Semaphore enforces per-group nullifier uniqueness, separate groups per app naturally prevent cross-app proof replay — no second circuit needed.
- **Credential state**: per-credential state is stored in a single `credentials` mapping (`bytes32 registrationHash => CredentialRecord`). The registration hash is `keccak256(registry, credentialGroupId, credentialId, appId)`, which ensures one credential per (credential group, app, credential identity) tuple while allowing different Semaphore commitments across apps.
- **Scope binding**: `submitProof` ties proofs to `msg.sender` + a context value, preventing proof replay across callers.
- **App-specific identities**: each app derives a unique Semaphore commitment from the user's `secret_base + app_id`.
- **Trusted verifiers**: multiple signers supported via `trustedVerifiers` mapping with `addTrustedVerifier`/`removeTrustedVerifier`. Supports TLSN, OAuth, zkPassport, etc.
- Semaphore groups are created on-chain via the Semaphore contract; the registry maps (credentialGroupId, appId) pairs to Semaphore group IDs via `appSemaphoreGroups`.
- **Custom app scoring**: Scores are managed by separate Scorer contracts implementing `IScorer`. A `DefaultScorer` (owned by BringID) holds global scores. Each app points to a scorer — `DefaultScorer` by default, or a custom implementation set via `setAppScorer()`. `submitProofs()` and `getScore()` call `apps[appId].scorer.getScore(credentialGroupId)` for each proof.
- **App self-registration**: Apps are registered via `registerApp(recoveryTimelock)` — public, auto-increment ID, caller becomes admin. App admins manage their own scorer (`setAppScorer`), recovery timelock (`setAppRecoveryTimelock`), admin transfer (`setAppAdmin`), suspension (`suspendApp`), and reactivation (`activateApp`).
- **Credential expiry**: per-credential-group `validityDuration` (seconds, 0 = no expiry). Set at `createCredentialGroup(id, validityDuration)` time and updatable via `setCredentialGroupValidityDuration()` (owner-only, affects future registrations/renewals only). On registration/renewal, `cred.expiresAt = block.timestamp + validityDuration` (skipped when 0). `removeExpiredCredential()` is public — anyone can call it after expiry to remove the commitment from the Semaphore group and set `cred.expired = true`. **`cred.registered` stays true and `cred.commitment` is NOT cleared** — this enforces commitment continuity on renewal and enables recovery. `cred.pendingRecovery` is cleared to avoid orphaned state. Between expiry and removal, the credential technically still works (removal must be triggered).
- **Register vs Renew separation**: `registerCredential()` is strictly for first-time registration — it rejects calls where `cred.registered` is true. `renewCredential()` handles all subsequent activations: it requires the same identity commitment as the original registration, re-adds the commitment to Semaphore if `cred.expired` is true, clears the expired flag, and resets the validity duration. Early renewal (before expiry) is allowed, effectively extending the credential. This prevents a **double-spend attack** where a user could change their commitment after expiry to obtain new Semaphore nullifiers for the same scope. Renewal is blocked during pending recovery (`require(cred.pendingRecovery.executeAfter == 0)`).
- **Attestation verification**: `verifyAttestation()` is a `public view` function that validates all common attestation checks (active credential group/app, registry address, expiry, ECDSA signature from trusted verifier) and returns the recovered signer address. Used internally by `registerCredential()`, `renewCredential()`, and `initiateRecovery()`.
- **Attestation expiry**: attestations include an `issuedAt` timestamp signed by the verifier. The contract enforces `block.timestamp <= issuedAt + attestationValidityDuration` (default 30 minutes). The owner can update the duration via `setAttestationValidityDuration()` (must be > 0).
- **Key recovery**: per-app timelocked commitment replacement. When a user loses their wallet, they re-authenticate via any supported verification flow (zkTLS, OAuth, zkPassport, zkKYC, etc.); the verifier re-derives the same `credentialId` and signs an attestation with a new commitment and the same `appId`. `initiateRecovery()` removes the old commitment from the per-app Semaphore group immediately and queues the new one behind the app's `recoveryTimelock`. `executeRecovery()` adds the new commitment after the timelock expires. App admin sets `recoveryTimelock` at `registerApp()` time (0 = disabled); can toggle on/off later via `setAppRecoveryTimelock()`. The `Attestation` struct includes `appId` for timelock lookup and per-app group resolution. `cred.commitment` tracks the current commitment per registration hash; `cred.pendingRecovery` tracks in-flight recovery requests.
- **Recovery on expired+removed credentials**: `initiateRecovery()` works even after a credential has expired and been removed from the Semaphore group. It checks `cred.registered` (which stays true after expiry), so a user who lost their key after expiry can still recover. When `cred.expired` is true, `_executeInitiateRecovery()` skips the `SEMAPHORE.removeMember()` call. `executeRecovery()` clears `cred.expired` and adds the new commitment to the Semaphore group. **Recovery does NOT modify `cred.expiresAt`** — key replacement and credential validity are independent concerns.
- **Error message convention**: all `require` error strings use a `BID::` prefix (e.g. `"BID::not registered"`, `"BID::app not active"`). This makes BringID errors instantly identifiable in transaction traces and logs. Keep messages short and lowercase after the prefix.
- **Expiry + recovery guard**: `removeExpiredCredential()` rejects calls when `cred.pendingRecovery.executeAfter != 0` (`"BID::recovery pending"`), preventing a double-remove from the Semaphore group after `initiateRecovery()` has already removed the commitment.

### Scripts (`script/`)

- **Deploy.s.sol** — `DeployDev` (dev with token), `DeployToken`, `Deploy` (production). Require `SEMAPHORE_ADDRESS` env var.
- **DeployLocal.s.sol** — Deploys SemaphoreVerifier, Semaphore, and CredentialRegistry for local e2e testing.
- **CredentialGroups.s.sol** — Batch-creates credential groups and sets scores on DefaultScorer.
- **RegisterApps.s.sol** — Batch-registers apps (public, auto-increment).
- **MockSignature.s.sol** — Generates test ECDSA signatures for attestations.
- **register-credential.mjs** — E2e script: derives Semaphore identity from `--secret-base` + `--app-id`, signs attestation, calls `registerCredential()`. Requires `PRIVATE_KEY`, `REGISTRY_ADDRESS` env vars.
- **verify-proof.mjs** — E2e script: generates Semaphore ZK proof and calls `submitProof()`. Requires `PRIVATE_KEY`, `REGISTRY_ADDRESS`, `SEMAPHORE_ADDRESS` env vars.

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
  node script/register-credential.mjs --credential-group-id 1 --app-id 1 --secret-base 42 --create-group

# 4. Submit proof (use REGISTRY_ADDRESS and SEMAPHORE_ADDRESS from deploy output)
PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  REGISTRY_ADDRESS=<addr> SEMAPHORE_ADDRESS=<addr> \
  node script/verify-proof.mjs --credential-group-id 1 --app-id 1 --secret-base 42 --context 0
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
