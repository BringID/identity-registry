import { ethers } from "ethers";
import { Identity, generateProof, Group } from "@semaphore-protocol/core";

// Parse --message flag (optional, backward-compatible)
let messageValue = "verification";
const positionalArgs = [];

for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === "--message" && i + 1 < process.argv.length) {
        messageValue = process.argv[i + 1];
        i++; // skip the value
    } else {
        positionalArgs.push(process.argv[i]);
    }
}

const privateKey = positionalArgs[0];
const scope = positionalArgs[1];

if (positionalArgs.length < 3) {
    console.log("Usage: node proof.mjs <privateKey> <scope> <groupCommitments...> [--message <hex>]");
    process.exit(1);
}

const identity = Identity.import(privateKey);
const group = new Group();
for (let i = 2; i < positionalArgs.length; i++) {
    group.addMember(positionalArgs[i]);
}

const {
    merkleTreeDepth, merkleTreeRoot, nullifier, message, points
} = await generateProof(
    identity, group, messageValue, scope
);

console.log(
    (new ethers.AbiCoder).encode(
        ["uint256", "uint256", "uint256", "uint256", "uint256[8]"],
        [merkleTreeDepth, merkleTreeRoot, nullifier, message, points]
    )
);
process.exit(0);
