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

## Architecture

### Core contracts (`src/registry/`)

- **CredentialRegistry.sol** — Main contract. Owner creates credential groups (metadata only — status). Per-app Semaphore groups are created lazily on first credential registration for each (credentialGroup, app) pair via `appSemaphoreGroups` mapping. Users `registerCredential()` with a verifier-signed attestation (which includes `appId`). Proof API has state-changing and view variants: `submitProof()` / `submitProofs()` consume Semaphore nullifiers (binding proofs to the caller via `scope == keccak256(abi.encode(msg.sender, context))`); `verifyProof()` / `verifyProofs()` are view-only counterparts using Semaphore's `verifyProof()` that don't consume nullifiers; `getScore()` is a view that verifies proofs and returns the aggregate score. Since each app has its own Semaphore group, cross-app proof replay is naturally prevented. Supports multiple trusted verifiers (`trustedVerifiers` mapping) for different verification methods (TLSN, OAuth, zkPassport, etc.). Per-app timelocked key recovery via `initiateRecovery()` / `executeRecovery()` — see Key Recovery section below. Deploys a `DefaultScorer` in the constructor.
- **ICredentialRegistry.sol** — Interface with core data types: `CredentialGroup` (status only), `App` (status + recoveryTimelock + admin + scorer), `RecoveryRequest` (credentialGroupId + appId + newCommitment + executeAfter), `Attestation` (registry + credentialGroupId + credentialId + appId + commitment), `CredentialGroupProof` (credentialGroupId + appId + semaphoreProof).
- **IScorer.sol** — Interface for scorer contracts: `getScore(uint256 credentialGroupId) → uint256`.
- **DefaultScorer.sol** — Default scorer owned by BringID. Stores global scores per credential group via `setScore()` / `getScore()`. Deployed automatically by the CredentialRegistry constructor.
- **Events.sol** — Event declarations.

### Key design decisions

- **Ownable2Step** (OpenZeppelin) for admin operations — two-step ownership transfer.
- **Per-app Semaphore groups**: each (credentialGroup, app) pair gets its own Semaphore group, created lazily on first registration. Since Semaphore enforces per-group nullifier uniqueness, separate groups per app naturally prevent cross-app proof replay — no second circuit needed.
- **Credential deduplication**: `credentialRegistered[keccak256(registry, credentialGroupId, credentialId, appId)]` prevents the same user from registering a credential twice for the same app, but allows different Semaphore commitments across apps.
- **Scope binding**: `submitProof` ties proofs to `msg.sender` + a context value, preventing proof replay across callers.
- **App-specific identities**: each app derives a unique Semaphore commitment from the user's `secret_base + app_id`.
- **Trusted verifiers**: multiple signers supported via `trustedVerifiers` mapping with `addTrustedVerifier`/`removeTrustedVerifier`. Supports TLSN, OAuth, zkPassport, etc.
- Semaphore groups are created on-chain via the Semaphore contract; the registry maps (credentialGroupId, appId) pairs to Semaphore group IDs via `appSemaphoreGroups`.
- **Custom app scoring**: Scores are managed by separate Scorer contracts implementing `IScorer`. A `DefaultScorer` (owned by BringID) holds global scores. Each app points to a scorer — `DefaultScorer` by default, or a custom implementation set via `setAppScorer()`. `submitProofs()` and `getScore()` call `apps[appId].scorer.getScore(credentialGroupId)` for each proof.
- **App self-registration**: Apps are registered via `registerApp(recoveryTimelock)` — public, auto-increment ID, caller becomes admin. App admins manage their own scorer (`setAppScorer`), recovery timelock (`setAppRecoveryTimelock`), and admin transfer (`setAppAdmin`). Owner retains `suspendApp()`.
- **Key recovery**: per-app timelocked commitment replacement. When a user loses their wallet, they re-authenticate via OAuth; the verifier re-derives the same `credentialId` and signs an attestation with a new commitment and the same `appId`. `initiateRecovery()` removes the old commitment from the per-app Semaphore group immediately and queues the new one behind the app's `recoveryTimelock`. `executeRecovery()` adds the new commitment after the timelock expires. App admin sets `recoveryTimelock` at `registerApp()` time (0 = disabled); can toggle on/off later via `setAppRecoveryTimelock()`. The `Attestation` struct includes `appId` for timelock lookup and per-app group resolution. `registeredCommitments` mapping tracks the current commitment per registration hash; `pendingRecoveries` mapping tracks in-flight recovery requests.

### Scripts (`script/`)

- **Deploy.s.sol** — `DeployDev` (dev with token), `DeployToken`, `Deploy` (production). Require `SEMAPHORE_ADDRESS` env var.
- **DeployLocal.s.sol** — Deploys SemaphoreVerifier, Semaphore, and CredentialRegistry for local e2e testing.
- **CredentialGroups.s.sol** — Batch-creates credential groups and sets scores on DefaultScorer.
- **RegisterApps.s.sol** — Batch-registers apps (public, auto-increment).
- **MockSignature.s.sol** — Generates test ECDSA signatures for attestations.

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
