#!/usr/bin/env node

// Register a credential on-chain.
//
// Creates a Semaphore identity from a secretBase + appId, builds an Attestation
// struct (now includes appId), signs it with the deployer key (which must be a
// trusted verifier), and calls registerCredential() on the CredentialRegistry.
//
// Required env vars:
//   PRIVATE_KEY            — deployer / trusted-verifier private key (hex, no 0x prefix)
//   REGISTRY_ADDRESS       — deployed CredentialRegistry address
//   BASE_RPC_URL           — JSON-RPC endpoint (defaults to http://127.0.0.1:8545)
//
// Usage:
//   node script/register-credential.mjs --credential-group-id 1 --app-id 1 --secret-base <bigint> [--create-group] [--credential-id <hex>]

import { ethers } from "ethers";
import { poseidon2 } from "poseidon-lite/poseidon2";
import { mulPointEscalar, Base8, subOrder } from "@zk-kit/baby-jubjub";
import { parseArgs } from "node:util";

// ── CLI args ────────────────────────────────────────────────────────────────

const { values: args } = parseArgs({
    options: {
        "credential-group-id": { type: "string" },
        "app-id": { type: "string" },
        "secret-base": { type: "string" },
        "credential-id": { type: "string" },
        "create-group": { type: "boolean", default: false },
    },
});

const credentialGroupId = BigInt(args["credential-group-id"] ?? "1");
const appId = BigInt(args["app-id"] ?? "1");

if (!args["secret-base"]) {
    console.error(
        "Usage: node script/register-credential.mjs --secret-base <bigint> [--credential-group-id 1] [--app-id 1] [--create-group] [--credential-id <hex>]"
    );
    process.exit(1);
}

const secretBase = BigInt(args["secret-base"]);

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

const RPC_URL = process.env.BASE_RPC_URL || "http://127.0.0.1:8545";

// ── Setup ───────────────────────────────────────────────────────────────────

const provider = new ethers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const wallet = new ethers.NonceManager(signer);

// Minimal ABI — only the functions we call / read
const registryAbi = [
    "function registerCredential((address registry, uint256 credentialGroupId, bytes32 credentialId, uint256 appId, uint256 semaphoreIdentityCommitment) attestation, uint8 v, bytes32 r, bytes32 s)",
    "function credentialGroups(uint256) view returns (uint8 status, uint256 validityDuration)",
    "function trustedVerifiers(address) view returns (bool)",
    "function createCredentialGroup(uint256 credentialGroupId, uint256 validityDuration)",
    "function appIsActive(uint256) view returns (bool)",
];

const registry = new ethers.Contract(REGISTRY_ADDRESS, registryAbi, wallet);

// ── Identity (secretBase + appId → Semaphore commitment) ─────────────────

// identitySecret = poseidon2([secretBase, appId])
const identitySecret = poseidon2([secretBase, appId]);

// The Semaphore v4 circuit requires secret < subOrder (BabyJubJub prime subgroup order).
// Since Base8 generates a cyclic subgroup of order subOrder, the publicKey is the same
// whether we use identitySecret or identitySecret % subOrder.
const secretScalar = identitySecret % subOrder;

// Derive Semaphore v4 public key: publicKey = Base8 * secretScalar
const publicKey = mulPointEscalar(Base8, secretScalar);

// commitment = poseidon2(publicKey)  — matches Semaphore Identity.commitment
const commitment = poseidon2(publicKey);

console.log("Secret base:    ", secretBase.toString());
console.log("App ID:         ", appId.toString());
console.log("Identity secret:", identitySecret.toString());
console.log("Commitment:     ", commitment.toString());

// ── Credential ID ───────────────────────────────────────────────────────────

// credentialId is a bytes32 that uniquely identifies this credential.
// In production, the verifier derives it as hash(oauth_id, app_id, verifier_private_key).
// For testing, we derive it from the secretBase.
const credentialId =
    args["credential-id"] ??
    ethers.keccak256(
        ethers.solidityPacked(
            ["string", "uint256", "uint256"],
            ["credential-id", secretBase, appId]
        )
    );

console.log("Credential ID:  ", credentialId);

// ── Ensure credential group exists ───────────────────────────────────────────

const [groupStatus] = await registry.credentialGroups(credentialGroupId);
if (groupStatus !== 1n) {
    if (args["create-group"]) {
        console.log(`Creating credential group ${credentialGroupId}...`);
        const cgTx = await registry.createCredentialGroup(credentialGroupId, 0);
        await cgTx.wait();
        console.log("Credential group created (tx:", cgTx.hash + ")");
        // Wait for node to index the new state before sending the next tx
        await new Promise((r) => setTimeout(r, 2000));
    } else {
        console.error(
            `Credential group ${credentialGroupId} is not active (status=${groupStatus}). ` +
                `Pass --create-group to create it, or create it manually first.`
        );
        process.exit(1);
    }
}

const appActive = await registry.appIsActive(appId);
if (!appActive) {
    console.error(`App ${appId} is not active. Register the app first.`);
    process.exit(1);
}

const isTrusted = await registry.trustedVerifiers(signer.address);
if (!isTrusted) {
    console.error(
        `Wallet ${signer.address} is not a trusted verifier on the registry.`
    );
    process.exit(1);
}

// ── Build & sign attestation ────────────────────────────────────────────────

const attestation = {
    registry: REGISTRY_ADDRESS,
    credentialGroupId,
    credentialId,
    appId,
    semaphoreIdentityCommitment: commitment,
};

// Encode the attestation the same way Solidity does:
//   keccak256(abi.encode(attestation))
const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256", "bytes32", "uint256", "uint256"],
    [
        attestation.registry,
        attestation.credentialGroupId,
        attestation.credentialId,
        attestation.appId,
        attestation.semaphoreIdentityCommitment,
    ]
);

const attestationHash = ethers.keccak256(encoded);

// EIP-191 personal sign (matches ECDSA.toEthSignedMessageHash in Solidity)
const signature = signer.signingKey.sign(
    ethers.hashMessage(ethers.getBytes(attestationHash))
);

console.log("\nSending registerCredential tx...");

// ── Send tx ─────────────────────────────────────────────────────────────────

const tx = await registry.registerCredential(
    [
        attestation.registry,
        attestation.credentialGroupId,
        attestation.credentialId,
        attestation.appId,
        attestation.semaphoreIdentityCommitment,
    ],
    signature.v,
    signature.r,
    signature.s
);

console.log("Tx hash:", tx.hash);
const receipt = await tx.wait();
console.log("Confirmed in block:", receipt.blockNumber);
console.log("Gas used:", receipt.gasUsed.toString());

// ── Output for verify-proof script ──────────────────────────────────────────

console.log("\n=== Save these for verify-proof.mjs ===");
console.log(`SECRET_BASE=${secretBase}`);
console.log(`APP_ID=${appId}`);
console.log(`CREDENTIAL_GROUP_ID=${credentialGroupId}`);
console.log(`COMMITMENT=${commitment.toString()}`);
