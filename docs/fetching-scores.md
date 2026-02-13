# Fetching Scores

The `DefaultScorer` contract stores global scores for each credential group. Scores can be read on-chain in a single call — no iteration or multicall needed.

**DefaultScorer address (Base mainnet & Sepolia):** `0xcE4A14a929FfF47df30216f4C8fa8907825F494F`

## Get All Scores

`getAllScores()` returns every credential group ID that has a score set, along with the corresponding values.

### cast (Foundry)

```bash
cast call 0xcE4A14a929FfF47df30216f4C8fa8907825F494F \
  "getAllScores()(uint256[],uint256[])" \
  --rpc-url $BASE_RPC_URL
```

### ethers.js

```js
const scorer = new ethers.Contract(
  "0xcE4A14a929FfF47df30216f4C8fa8907825F494F",
  ["function getAllScores() view returns (uint256[], uint256[])"],
  provider
);
const [groupIds, scores] = await scorer.getAllScores();
// groupIds: [1n, 2n, 3n, ...]
// scores:   [2n, 5n, 10n, ...]
```

### viem

```js
const [groupIds, scores] = await publicClient.readContract({
  address: "0xcE4A14a929FfF47df30216f4C8fa8907825F494F",
  abi: [{
    name: "getAllScores",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256[]" }, { type: "uint256[]" }],
  }],
  functionName: "getAllScores",
});
```

## Get Specific Scores

For fetching a subset of scores by credential group ID:

### Single group

```js
// ethers.js
const scorer = new ethers.Contract(address, [
  "function getScore(uint256) view returns (uint256)",
], provider);
const score = await scorer.getScore(1); // Farcaster Low → 2
```

### Batch by IDs

```js
// ethers.js
const scorer = new ethers.Contract(address, [
  "function getScores(uint256[]) view returns (uint256[])",
], provider);
const scores = await scorer.getScores([1, 4, 10]); // Farcaster Low, GitHub Low, zkPassport
```

## Apps With Custom Scorers

Each app can set a custom scorer contract via `setAppScorer()`. Apps that don't set one use the `DefaultScorer` by default.

To resolve the scorer for a specific app:

```js
const registry = new ethers.Contract(REGISTRY_ADDRESS, [
  "function apps(uint256) view returns (uint8 status, uint256 recoveryTimelock, address admin, address scorer)",
], provider);
const app = await registry.apps(appId);
const scorerAddress = app.scorer;
```

Then call `getAllScores()`, `getScores()`, or `getScore()` on that address. Custom scorers implement `IScorer` (which requires `getScore(uint256)`); `getAllScores()` and `getScores()` are only available if the custom scorer extends `DefaultScorer` or implements them separately.
