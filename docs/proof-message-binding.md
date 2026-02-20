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

The `@bringid/contracts` package provides three abstraction levels. All handle message binding; the higher-level contracts also enforce app ID matching and proof count limits.

### Recommended: `BringIDGatedWithContext`

Handles message binding, app ID validation, proof count limits, and proof submission in a single `_submitAndValidate` call. Your contract only needs to check the returned score.

```solidity
import {BringIDGatedWithContext} from "@bringid/contracts/BringIDGatedWithContext.sol";
import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";

contract MyAirdrop is BringIDGatedWithContext {
    uint256 public immutable MIN_SCORE;
    error InsufficientScore(uint256 score, uint256 minScore);

    constructor(
        ICredentialRegistry registry_,
        uint256 minScore_,
        uint256 context_,
        uint256 appId_,
        uint256 maxProofs_
    ) BringIDGatedWithContext(registry_, context_, appId_, maxProofs_) {
        MIN_SCORE = minScore_;
    }

    function claim(
        address recipient_,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs_
    ) external {
        uint256 score = _submitAndValidate(recipient_, proofs_);
        if (score < MIN_SCORE) revert InsufficientScore(score, MIN_SCORE);
        // ... distribute tokens to recipient_ ...
    }
}
```

For dynamic context values, inherit `BringIDGated` directly and pass context as a parameter to the 3-argument `_submitAndValidate(recipient, context, proofs)`.

### Low-level: `SafeProofConsumer`

For full control (custom validation logic, non-standard message semantics), inherit `SafeProofConsumer` and call the registry directly:

```solidity
import {SafeProofConsumer} from "@bringid/contracts/SafeProofConsumer.sol";

contract MyCustomConsumer is SafeProofConsumer {
    constructor(ICredentialRegistry registry_)
        SafeProofConsumer(registry_)
    {}

    function claim(
        address recipient_,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs_
    ) external {
        // Validates message == hash(recipient) for every proof
        _validateMessageBindings(proofs_, recipient_);

        // Forward to registry (safe — message is bound)
        uint256 score = REGISTRY.submitProofs(CONTEXT, proofs_);

        // ... distribute tokens to recipient_ ...
    }
}
```

The helper computes `expectedMessage(recipient) = uint256(keccak256(abi.encodePacked(recipient)))` and checks that every proof's `semaphoreProof.message` matches.

### Contract hierarchy

```
SafeProofConsumer (REGISTRY)          ← message binding only
    │
BringIDGated (APP_ID, MAX_PROOFS)    ← + app ID validation, proof count, _submitAndValidate(recipient, context, proofs)
    │
BringIDGatedWithContext (CONTEXT)     ← + fixed context, _submitAndValidate(recipient, proofs)
```

### SafeProofConsumer API

| Function | Visibility | Description |
|----------|-----------|-------------|
| `expectedMessage(address)` | `public pure` | Returns the expected message value for a recipient. Use off-chain to set the message when generating proofs. |
| `_validateMessageBinding(proof, recipient)` | `internal pure` | Validates a single proof's message binding. Reverts `ZeroRecipient` or `MessageBindingMismatch`. |
| `_validateMessageBindings(proofs, recipient)` | `internal pure` | Validates all proofs in an array. |

### BringIDGated API

| Function | Visibility | Description |
|----------|-----------|-------------|
| `_submitAndValidate(recipient, context, proofs)` | `internal` | Validates proof count, app IDs, message binding, submits proofs. Returns aggregate score. |

### BringIDGatedWithContext API

| Function | Visibility | Description |
|----------|-----------|-------------|
| `_submitAndValidate(recipient, proofs)` | `internal` | Same as above but uses the stored `CONTEXT` immutable. |

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

In these cases, do **not** use `SafeProofConsumer`. Instead, compute your custom expected message and check it manually:

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

For most integrations, inherit `BringIDGatedWithContext` (or `BringIDGated` for dynamic context) — these handle both message binding and proof submission. Only use `SafeProofConsumer` directly if you need custom validation logic.
