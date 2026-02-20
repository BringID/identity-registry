## BringID Credential Registry

Privacy-preserving credential system built with Semaphore zero-knowledge proofs. Users register credentials via verifier-signed attestations, then prove membership without revealing their identity.

## Deployed Contracts

Contract addresses are identical on both chains (same deployer, same nonce).

### Base Mainnet (chain ID 8453)

| Contract | Address |
|---|---|
| Semaphore | [`0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`](https://basescan.org/address/0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D) |
| CredentialRegistry | [`0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe`](https://basescan.org/address/0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe) |
| DefaultScorer | [`0x6a0b5ba649C7667A0C4Cd7FE8a83484AEE6C5345`](https://basescan.org/address/0x6a0b5ba649C7667A0C4Cd7FE8a83484AEE6C5345) |
| ScorerFactory | [`0x05321FAAD6315a04d5024Ee5b175AB1C62a3fd44`](https://basescan.org/address/0x05321FAAD6315a04d5024Ee5b175AB1C62a3fd44) |

### Base Sepolia (chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | [`0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`](https://sepolia.basescan.org/address/0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D) |
| CredentialRegistry | [`0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe`](https://sepolia.basescan.org/address/0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe) |
| DefaultScorer | [`0x6a0b5ba649C7667A0C4Cd7FE8a83484AEE6C5345`](https://sepolia.basescan.org/address/0x6a0b5ba649C7667A0C4Cd7FE8a83484AEE6C5345) |
| ScorerFactory | [`0x05321FAAD6315a04d5024Ee5b175AB1C62a3fd44`](https://sepolia.basescan.org/address/0x05321FAAD6315a04d5024Ee5b175AB1C62a3fd44) |

### Credential Groups

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
| 10 | zkPassport | — | — | 20 | 180 days |
| 11 | Self | — | — | 20 | 180 days |
| 12 | Uber Rides | — | — | 10 | 180 days |
| 13 | Apple Subs | — | — | 10 | 180 days |
| 14 | Binance KYC | — | — | 20 | 180 days |
| 15 | OKX KYC | — | — | 20 | 180 days |

## Integrating Proof Consumption (Front-Running Protection)

When a smart contract consumes BringID proofs on-chain (e.g. an airdrop or gating contract), the Semaphore `scope` is bound to `msg.sender` + `context`. This means any transaction routed through the same contract shares the same scope — an attacker can copy proofs from the mempool and front-run the original caller.

**Solution:** Bind the Semaphore `message` field to the intended recipient. The `@bringid/contracts` package provides `BringIDGated` — an abstract base that handles app ID validation, message binding, and proof submission. Your contract only needs to check the returned score.

### Quick start — `BringIDGated`

```solidity
import {BringIDGated} from "@bringid/contracts/BringIDGated.sol";
import {CredentialProof} from "@bringid/contracts/interfaces/Types.sol";

contract MyGate is BringIDGated {
    constructor(address registry_, uint256 appId_)
        BringIDGated(registry_, appId_)
    {}

    function doAction(
        address recipient_,
        CredentialProof[] calldata proofs_
    ) external {
        uint256 bringIDScore = _submitProofsForRecipient(recipient_, proofs_);
        // ... use bringIDScore ...
    }
}
```

### Off-chain proof generation

When generating proofs for a message-binding-aware contract, set the `message` to `keccak256(abi.encodePacked(recipientAddress))`:

```javascript
import { generateProof } from "@semaphore-protocol/core";
import { ethers } from "ethers";

const recipient = "0x1234...";
const message = ethers.solidityPackedKeccak256(["address"], [recipient]);

const proof = await generateProof(identity, group, message, scope);
```

See [`docs/proof-message-binding.md`](docs/proof-message-binding.md) for a full explanation of scope vs. message, why putting the recipient in `context` breaks sybil resistance, and patterns for custom message semantics. See [`contracts/examples/SimpleAirdrop.sol`](contracts/examples/SimpleAirdrop.sol) for a complete example. For custom message semantics beyond simple recipient binding, compute your own expected message and validate manually.

## Usage

### Install dependencies

This project uses `yarn` to install dependencies since `soldeer` doesn't resolve them correctly.
```shell
yarn
```

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
