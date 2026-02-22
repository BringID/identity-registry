#!/usr/bin/env node

// Validate a Semaphore proof on-chain via the CredentialRegistry.
//
// Derives a deterministic Semaphore identity from the wallet private key +
// appId + credentialGroupId, generates a Semaphore ZK proof for a previously
// registered credential, and calls submitProof() on-chain.
//
// Identity derivation:
//   seed = keccak256(abi.encodePacked(walletPrivateKey, appId, credentialGroupId))
//   identity = new Identity(seed)
//
// Required env vars:
//   PRIVATE_KEY            — wallet private key (hex)
//   REGISTRY_ADDRESS       — deployed CredentialRegistry address
//   SEMAPHORE_ADDRESS      — deployed Semaphore contract address
//   BASE_RPC_URL           — JSON-RPC endpoint (defaults to http://127.0.0.1:8545)
//
// Usage:
//   node script/verify-proof.mjs \
//     --credential-group-id 1 \
//     --app-id 1 \
//     [--context 0]

import { ethers } from "ethers";
import { Identity, generateProof, Group } from "@semaphore-protocol/core";
import { SemaphoreEthers } from "@semaphore-protocol/data";
import { parseArgs } from "node:util";

// ── CLI args ────────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
    options: {
        "credential-group-id": { type: "string" },
        "app-id": { type: "string" },
        context: { type: "string" },
    },
});

const credentialGroupId = BigInt(args["credential-group-id"] ?? "1");
const appId = BigInt(args["app-id"] ?? "1");
const context = BigInt(args["context"] ?? "0");

// ── Env ─────────────────────────────────────────────────────────────────────

let PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) {
    console.error("PRIVATE_KEY env var is required");
    process.exit(1);
}
if (!PRIVATE_KEY.startsWith("0x")) PRIVATE_KEY = "0x" + PRIVATE_KEY;

const REGISTRY_ADDRESS = process.env.REGISTRY_ADDRESS;
if (!REGISTRY_ADDRESS) {
    console.error("REGISTRY_ADDRESS env var is required");
    process.exit(1);
}

const SEMAPHORE_ADDRESS = process.env.SEMAPHORE_ADDRESS;
if (!SEMAPHORE_ADDRESS) {
    console.error("SEMAPHORE_ADDRESS env var is required");
    process.exit(1);
}

const RPC_URL = process.env.BASE_RPC_URL || "http://127.0.0.1:8545";

// ── Setup ───────────────────────────────────────────────────────────────────

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

const registryAbi = [
    "function submitProof(uint256 appId, uint256 context, (uint256 credentialGroupId, uint256 appId, (uint256 merkleTreeDepth, uint256 merkleTreeRoot, uint256 nullifier, uint256 message, uint256 scope, uint256[8] points) semaphoreProof) proof)",
    "function credentialGroups(uint256) view returns (uint8 status, uint256 validityDuration, uint256 familyId)",
    "function appSemaphoreGroups(uint256, uint256) view returns (uint256)",
    "function appSemaphoreGroupCreated(uint256, uint256) view returns (bool)",
    "function apps(uint256) view returns (uint8 status, uint256 recoveryTimelock, address admin, address scorer)",
    "event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier)",
];

const registry = new ethers.Contract(REGISTRY_ADDRESS, registryAbi, wallet);

// ── Identity derivation ─────────────────────────────────────────────────────

// seed = keccak256(abi.encodePacked(walletPrivateKey, appId, credentialGroupId))
const seed = ethers.keccak256(
    ethers.solidityPacked(
        ["bytes32", "uint256", "uint256"],
        [PRIVATE_KEY, appId, credentialGroupId]
    )
);
const identity = new Identity(seed);

console.log("Wallet:             ", wallet.address);
console.log("App ID:             ", appId.toString());
console.log("Credential grp:     ", credentialGroupId.toString());
console.log("Identity commitment:", identity.commitment.toString());

// ── Pre-flight checks ───────────────────────────────────────────────────────

const [groupStatus] = await registry.credentialGroups(credentialGroupId);
if (groupStatus !== 1n) {
    console.error(
        `Credential group ${credentialGroupId} is not active (status=${groupStatus}).`
    );
    process.exit(1);
}

const [appStatus] = await registry.apps(appId);
if (appStatus !== 1n) {
    console.error(`App ${appId} is not active (status=${appStatus}).`);
    process.exit(1);
}

const groupCreated = await registry.appSemaphoreGroupCreated(credentialGroupId, appId);
if (!groupCreated) {
    console.error(
        `No Semaphore group exists for credential group ${credentialGroupId} + app ${appId}. Register a credential first.`
    );
    process.exit(1);
}

const semaphoreGroupId = await registry.appSemaphoreGroups(credentialGroupId, appId);
console.log("Semaphore group ID:", semaphoreGroupId.toString());

// ── Fetch group members ─────────────────────────────────────────────────────

console.log("Fetching group members from on-chain events...");

// Use START_BLOCK env to avoid scanning the entire chain on public RPCs.
// Default: current block minus 10000 (covers recent deployments).
const currentBlock = await provider.getBlockNumber();
const startBlock = process.env.START_BLOCK
    ? Number(process.env.START_BLOCK)
    : Math.max(0, currentBlock - 10000);

const semaphoreEthers = new SemaphoreEthers(RPC_URL, {
    address: SEMAPHORE_ADDRESS,
    startBlock,
});

const members = await semaphoreEthers.getGroupMembers(semaphoreGroupId.toString());
console.log(`Found ${members.length} member(s) in Semaphore group`);

if (members.length === 0) {
    console.error("Group has no members — register a credential first.");
    process.exit(1);
}

// Build a local Group with the on-chain members
const group = new Group();
for (const m of members) {
    if (m !== "0") {
        group.addMember(m);
    }
}

// ── Compute scope ───────────────────────────────────────────────────────────

// scope = keccak256(abi.encode(appId, msg.sender, context))
const scope = BigInt(
    ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
            ["uint256", "address", "uint256"],
            [appId, wallet.address, context]
        )
    )
);
console.log("Scope:", scope.toString());

// ── Generate Semaphore proof ────────────────────────────────────────────────

console.log("Generating Semaphore proof (this may take a moment)...");

const semaphoreProof = await generateProof(
    identity,
    group,
    "verification",
    scope
);

console.log("Semaphore proof generated:");
console.log("  Merkle tree depth:", semaphoreProof.merkleTreeDepth);
console.log("  Merkle tree root: ", semaphoreProof.merkleTreeRoot);
console.log("  Nullifier:        ", semaphoreProof.nullifier);
console.log("  Message:          ", semaphoreProof.message);

// ── Build CredentialGroupProof struct ───────────────────────────────────────

const proof = {
    credentialGroupId,
    appId,
    semaphoreProof: {
        merkleTreeDepth: semaphoreProof.merkleTreeDepth,
        merkleTreeRoot: semaphoreProof.merkleTreeRoot,
        nullifier: semaphoreProof.nullifier,
        message: semaphoreProof.message,
        scope: semaphoreProof.scope,
        points: semaphoreProof.points,
    },
};

// ── Send tx ─────────────────────────────────────────────────────────────────

console.log("\nSending submitProof tx...");

const tx = await registry.submitProof(appId, context, proof);
console.log("Tx hash:", tx.hash);

const receipt = await tx.wait();
console.log("Confirmed in block:", receipt.blockNumber);
console.log("Gas used:", receipt.gasUsed.toString());

// Parse events
for (const log of receipt.logs) {
    try {
        const parsed = registry.interface.parseLog(log);
        if (parsed && parsed.name === "ProofValidated") {
            console.log("\nProofValidated event:");
            console.log("  credentialGroupId:", parsed.args[0].toString());
            console.log("  appId:            ", parsed.args[1].toString());
            console.log("  nullifier:        ", parsed.args[2].toString());
        }
    } catch {
        // Not our event — skip
    }
}

console.log("\nProof validated successfully!");
