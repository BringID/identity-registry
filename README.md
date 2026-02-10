## BringID Identity Registry

Privacy-preserving credential system built with Semaphore zero-knowledge proofs. Users register credentials via verifier-signed attestations, then prove membership without revealing their identity.

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | [`0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`](https://sepolia.basescan.org/address/0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D) |
| CredentialRegistry | [`0x3353a67d5963C263F3c6F4dA3Fc45509981160A9`](https://sepolia.basescan.org/address/0x3353a67d5963C263F3c6F4dA3Fc45509981160A9) |
| DefaultScorer | [`0x8AD32E9076BDe94B4b31A0b7a283fed23dFe5af4`](https://sepolia.basescan.org/address/0x8AD32E9076BDe94B4b31A0b7a283fed23dFe5af4) |

### Credential Groups

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
