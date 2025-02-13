import { ChecksumMerkle } from './new/ChecksumMerkleNew.ts';
import { toBytes } from './new/MerkleTree.js';
import { MerkleProof, MerkleTree } from '../index.js';

const merkleNew = new ChecksumMerkle();
merkleNew.setBlockData(
    '0x000000000000000000003b485da71d761e3946459e33301e9227005014d32fe3',
    '0x6a1a20cf378c68b915be2d0f9a898f7006d874ce8ccf2a1d061ba688b3b8e8d1',
    '0x00000000000000000000c7430d04e6cce6e8f52e8d342528deb78fbf76939fe0',
    '0x000000000000000000020c661d8d78de9105a8d79a8fd8bc6b70e94a17762ef1',
    '0x0000000000000000000151f64e37678510ad013b25e6f4198c8fcb139079ca8c',
    '0x00000000000000000002e7eb918cbc3b0c30e7c924194d593d99949c334f89ea',
);

const proofsNew = merkleNew.getProofs();
if (!merkleNew.tree) throw new Error('Merkle tree not generated');

const p = new MerkleProof(merkleNew.tree.getProof(5).proofHashes());
console.log(merkleNew.tree, merkleNew.tree?.getProof(5).proofHashes(), p.verifyData(merkleNew.rootBytes, ChecksumMerkle.toBytes(merkleNew.values[5]!)));

const proofs = proofsNew![0][1].map((p) => toBytes(p));
console.log('proofs', proofs, merkleNew.rootBytes, merkleNew.values[0], (MerkleTree.hash(ChecksumMerkle.toBytes(merkleNew.values[0]!))));

const v = new MerkleProof(proofs).verify(
    merkleNew.rootBytes,
    MerkleTree.hash(ChecksumMerkle.toBytes(merkleNew.values[0]!)),
);

console.log(v);