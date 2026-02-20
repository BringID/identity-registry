# Proof Message Binding — Front-Running Protection

## The Problem: Mempool Front-Running

When a smart contract consumes BringID credential proofs (e.g. an airdrop contract), the Semaphore proof's `scope` is bound to `msg.sender` (the contract address) plus a `context` value. This means **any transaction routed through the same contract produces the same scope**.

An attacker monitoring the mempool can:

1. See Alice's pending `claim(alice, proofs)` transaction.
2. Copy the proofs and submit `claim(attacker, proofs)` with higher gas.
3. The attacker's transaction executes first — `msg.sender` is the same contract, so `scope` matches.
4. The nullifier is consumed, and the attacker receives the payout.
5. Alice's transaction reverts (nullifier already used).

This attack works because the proof is not bound to the *specific recipient* — only to the contract address.

## Scope vs. Message

Semaphore proofs have two free-form fields:

| Field | Purpose | Registry behavior |
|-------|---------|-------------------|
| `scope` | Drives nullifier uniqueness (anti-sybil). One valid proof per identity per scope. | **Validated**: must equal `keccak256(msg.sender, context)` |
| `message` | Arbitrary signal bound to the proof. Does not affect nullifiers. | **Not validated**: free for application use |

### Why not put the recipient in `context`?

If the recipient address were part of `context`, it would change the `scope`, which changes the nullifier. This means the same identity could generate valid proofs for *every* recipient address — completely breaking sybil resistance. A user could claim from address A, then claim again from address B with a fresh nullifier.

The `message` field is the correct place for recipient binding because it is verified by the ZK proof (the prover committed to this value) but does **not** affect the nullifier.

## The Solution: Message Binding

The `@bringid/contracts` package provides `BringIDGated` — an abstract base that handles message binding, app ID validation, and proof submission in a single `_submitProofsForRecipient` call. Your contract only needs to check the returned score. Context defaults to `0`; use the 3-parameter overload for a custom context.

### Recommended: `BringIDGated`

```solidity
import {BringIDGated} from "@bringid/contracts/BringIDGated.sol";
import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";

contract MyGate is BringIDGated {
    constructor(ICredentialRegistry registry_, uint256 appId_)
        BringIDGated(registry_, appId_)
    {}

    function doAction(
        address recipient_,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs_
    ) external {
        uint256 bringIDScore = _submitProofsForRecipient(recipient_, proofs_);
        // ... use bringIDScore ...
    }
}
```

For a non-zero fixed context, store your own `CONTEXT` immutable and call the 3-parameter overload `_submitProofsForRecipient(recipient, CONTEXT, proofs)` directly.

### BringIDGated API

| Function | Visibility | Description |
|----------|-----------|-------------|
| `expectedMessage(address)` | `public pure` | Returns the expected message value for a recipient. Use off-chain to set the message when generating proofs. |
| `_validateRecipientBinding(proof, recipient)` | `internal pure` | Validates a single proof's recipient binding. Reverts `ZeroRecipient` or `MessageBindingMismatch`. |
| `_validateRecipientBindings(proofs, recipient)` | `internal pure` | Validates all proofs in an array. |
| `_submitProofsForRecipient(recipient, proofs)` | `internal virtual` | Validates app IDs, message binding, submits proofs with context=0. Returns aggregate score. |
| `_submitProofsForRecipient(recipient, context, proofs)` | `internal` | Validates app IDs, message binding, submits proofs with explicit context. Returns aggregate score. |

## Off-Chain Proof Generation

When generating Semaphore proofs for a message-binding-aware contract, set the `message` parameter to `hash(recipientAddress)`:

```javascript
import { generateProof } from "@semaphore-protocol/core";
import { ethers } from "ethers";

const recipient = "0x1234..."; // the address that will receive the airdrop
const message = ethers.solidityPackedKeccak256(["address"], [recipient]);

const proof = await generateProof(
    identity,
    group,
    message,  // bound to recipient
    scope     // bound to contract + context (as usual)
);
```

## Custom Message Semantics

Not all use cases bind the message to a simple recipient address. You may want to bind to:

- A tuple of `(recipient, amount)` for variable payouts
- An action hash for governance voting
- A commitment to off-chain data

In these cases, do **not** use the built-in message binding helpers. Instead, compute your custom expected message and check it manually:

```solidity
uint256 expectedMsg = uint256(keccak256(abi.encode(recipient, amount)));
require(proof.semaphoreProof.message == expectedMsg, "message mismatch");
```

The key principle is the same: the proof's `message` field must commit to all action-specific parameters that an attacker could substitute.

## Summary

| Layer | What it prevents | Field |
|-------|-----------------|-------|
| Scope binding (`msg.sender + context`) | Cross-contract replay, sybil (one proof per identity per scope) | `scope` |
| Message binding (`hash(recipient)`) | Mempool front-running within the same contract | `message` |

Both layers are needed for safe on-chain proof consumption. The registry enforces scope binding; your contract must enforce message binding.

For most integrations, inherit `BringIDGated` — it handles message binding, app ID validation, and proof submission. For custom message semantics, compute your own expected message and validate manually.
