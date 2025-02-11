import { MerkleTree } from '../index.js';
import { toBytes } from './new/MerkleTree.js';

const leaves = [
    toBytes('0x000000000000000000003b485da71d761e3946459e33301e9227005014d32fe3'),
    toBytes('0x6a1a20cf378c68b915be2d0f9a898f7006d874ce8ccf2a1d061ba688b3b8e8d1'),
    toBytes('0x00000000000000000000c7430d04e6cce6e8f52e8d342528deb78fbf76939fe0'),
    toBytes('0x000000000000000000020c661d8d78de9105a8d79a8fd8bc6b70e94a17762ef1'),
    toBytes('0x0000000000000000000151f64e37678510ad013b25e6f4198c8fcb139079ca8c'),
    toBytes('0x00000000000000000002e7eb918cbc3b0c30e7c924194d593d99949c334f89ea'),
];

// Build the Merkle tree
const tree = new MerkleTree(leaves); // calls the constructor from your TS interface
const root = tree.root();            // get the Merkle root (Uint8Array)

// For each leaf, build and verify its proof
for (const leafData of leaves) {
    // Rust does "MerkleTreeSha256::hash_leaf(leaf_data)" => TS: "MerkleTree.hash(leafData)"
    const leafHash = MerkleTree.hash(leafData);

    // Retrieve index of this hashed leaf
    const idx = tree.getIndexHash(leafHash);

    // Build the proof
    const proof = tree.getProof(idx);

    const verified = proof.verify(root, leafHash);
    console.log('validating proof for leaf_data:', (leafData), verified);

    // Equivalent to Rust's `assert!(...)`
    if (!verified) {
        throw new Error(
            `Proof for leaf_data '${new TextDecoder().decode(leafData)}' must verify`,
        );
    }
}
