# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BringID Identity Registry — Solidity smart contracts for a privacy-preserving credential system. Users join credential groups via TLSN-verified attestations, then prove membership using Semaphore zero-knowledge proofs. Each credential group carries a score; the `score()` function aggregates scores across multiple credential proofs.

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

- **CredentialRegistry.sol** — Main contract. Owner creates credential groups (each with a score and backing Semaphore group). Users `joinGroup()` with a TLSN-signed attestation. Proof validation via `validateProof()` checks the Semaphore ZK proof and enforces that `scope == keccak256(abi.encode(msg.sender, context))`, binding proofs to the caller. `score()` validates multiple proofs and sums their group scores.
- **ICredentialRegistry.sol** — Interface with core data types: `CredentialGroup` (score + semaphoreGroupId + status), `Attestation` (registry + credentialGroupId + idHash + commitment), `CredentialGroupProof`.
- **Events.sol** — Event declarations.

### Key design decisions

- **Ownable2Step** (OpenZeppelin) for admin operations — two-step ownership transfer.
- **Nonce deduplication**: `keccak256(registry, credentialGroupId, idHash)` prevents the same user from joining a group twice, but allows different Semaphore commitments across groups.
- **Scope binding**: `validateProof` ties proofs to `msg.sender` + a context value, preventing proof replay across callers.
- Semaphore groups are created on-chain via the Semaphore contract; the registry maps its own credential group IDs to Semaphore group IDs.

### Scripts (`script/`)

- **Deploy.s.sol** — `DeployDev` (dev with token), `DeployToken`, `Deploy` (production). All require `SEMAPHORE_ADDRESS` env var.
- **CredentialGroups.s.sol** — Batch-creates credential groups with predefined scores.
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

GitHub Actions (`.github/workflows/test.yml`): format check → build with sizes → test (`forge test -vvv`). Triggered on push, PR, and manual dispatch.

### Foundry config (`foundry.toml`)

- `via_ir = true`, optimizer with 200 runs
- Fuzz: 10 runs, 100 max rejections
