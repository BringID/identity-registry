## BringID Identity Registry

Privacy-preserving credential system built with Semaphore zero-knowledge proofs. Users register credentials via verifier-signed attestations, then prove membership without revealing their identity.

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | [`0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`](https://sepolia.basescan.org/address/0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D) |
| CredentialRegistry | [`0xB0e2bf7d3D6536ad4b5851533bb120C9dbF5493b`](https://sepolia.basescan.org/address/0xB0e2bf7d3D6536ad4b5851533bb120C9dbF5493b) |
| DefaultScorer | [`0x24EDA18506D9509F438c53496274A2fA4675888F`](https://sepolia.basescan.org/address/0x24EDA18506D9509F438c53496274A2fA4675888F) |

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
