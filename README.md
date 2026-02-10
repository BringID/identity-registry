## BringID Identity Registry

Privacy-preserving credential system built with Semaphore zero-knowledge proofs. Users register credentials via verifier-signed attestations, then prove membership without revealing their identity.

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | [`0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`](https://sepolia.basescan.org/address/0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D) |
| CredentialRegistry | [`0x3353a67d5963C263F3c6F4dA3Fc45509981160A9`](https://sepolia.basescan.org/address/0x3353a67d5963C263F3c6F4dA3Fc45509981160A9) |
| DefaultScorer | [`0x8AD32E9076BDe94B4b31A0b7a283fed23dFe5af4`](https://sepolia.basescan.org/address/0x8AD32E9076BDe94B4b31A0b7a283fed23dFe5af4) |

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
