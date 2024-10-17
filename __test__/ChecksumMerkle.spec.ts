import test from 'ava'

import { BufferHelper } from '@btc-vision/bsi-binary'
import { MerkleTree, MerkleProof } from '..'
import { defaultAbiCoder } from '@ethersproject/abi'
import { arrayify as toBytes, hexlify as toHex } from '@ethersproject/bytes'
import { ZERO_HASH } from './types/ZeroValue.js'
import { BlockHeaderChecksumProof } from './types/IBlockHeaderDocument.js'
import { StandardMerkleTree } from '@btc-vision/merkle-tree'


// Old reference from @btc-vision/merkle-tree-sha256
export class ChecksumMerkleOld {
    public static TREE_TYPE: [string, string] = ['uint8', 'bytes32'];
    public tree: StandardMerkleTree<[number, Uint8Array]> | undefined;
    public values: [number, Uint8Array][] = [];

    public get root(): string {
        if (!this.tree) {
            throw new Error('[Checksum] Merkle tree not generated (Get root)');
        }

        return this.tree.root;
    }

    public static verify(
        root: string,
        type: [string, string],
        value: [number, Uint8Array],
        proof: string[],
    ): boolean {
        return StandardMerkleTree.verify<[number, Uint8Array]>(root, type, value, proof);
    }

    public validate(): void {
        if (!this.tree) {
            throw new Error('[Checksum] Merkle tree not generated');
        }

        this.tree.validate();
    }

    public setBlockData(
        previousBlockHash: string,
        previousBlockChecksum: string,
        blockHash: string,
        blockMerkleRoot: string,
        blockStateRoot: string,
        blockReceiptRoot: string,
    ): void {
        this.values.push([0, BufferHelper.hexToUint8Array(previousBlockHash || ZERO_HASH)]);
        this.values.push([1, BufferHelper.hexToUint8Array(previousBlockChecksum || ZERO_HASH)]);
        this.values.push([2, BufferHelper.hexToUint8Array(blockHash || ZERO_HASH)]);
        this.values.push([3, BufferHelper.hexToUint8Array(blockMerkleRoot || ZERO_HASH)]);
        this.values.push([4, BufferHelper.hexToUint8Array(blockStateRoot || ZERO_HASH)]);
        this.values.push([5, BufferHelper.hexToUint8Array(blockReceiptRoot || ZERO_HASH)]);

        this.generateTree();
    }

    public getProofs(): BlockHeaderChecksumProof {
        if (!this.tree) {
            throw new Error('Merkle tree not generated');
        }

        this.validate();

        const proofs: BlockHeaderChecksumProof = [];
        for (let i = 0; i < this.values.length; i++) {
            const proof: string[] = this.tree.getProof(this.values[i]);

            if (!proof || !proof.length) {
                throw new Error(`Proof not found for ${this.values[i][0]}`);
            }

            proofs.push([this.values[i][0], proof]);
        }

        return proofs;
    }

    private generateTree(): void {
        if (this.tree) {
            throw new Error('Checksum Merkle tree already generated');
        }

        this.tree = StandardMerkleTree.of<[number, Uint8Array]>(
            this.values,
            ChecksumMerkleOld.TREE_TYPE,
            {
                sortLeaves: true,
            },
        );
    }
}

// New implementation of ChecksumMerkle
export class ChecksumMerkleNew {
    public static TREE_TYPE: [string, string] = ['uint8', 'bytes32'];
    public tree: MerkleTree | undefined
    public values: [number, Uint8Array][] = [];

    public static toBytes(value: any): Uint8Array {
        const data = defaultAbiCoder.encode(ChecksumMerkleNew.TREE_TYPE, value)
        const result = toBytes(data)
        return result
    }

    public get root(): string | null {
        if (!this.tree) {
            throw new Error('[Checksum] Merkle tree not generated (Get root)');
        }
        return this.tree.rootHex()
    }

    public static verify(
        root: string,
        hash: Uint8Array,
        proof: string[],
    ): boolean {
        return new MerkleProof(proof.map(p => toBytes(p))).verify(toBytes(root), hash)

    }

    public validate(): void {
        if (!this.tree) {
            throw new Error('[Checksum] Merkle tree not generated');
        }
    }

    public setBlockData(
        previousBlockHash: string,
        previousBlockChecksum: string,
        blockHash: string,
        blockMerkleRoot: string,
        blockStateRoot: string,
        blockReceiptRoot: string,
    ): void {
        this.values.push([0, BufferHelper.hexToUint8Array(previousBlockHash || ZERO_HASH)]);
        this.values.push([1, BufferHelper.hexToUint8Array(previousBlockChecksum || ZERO_HASH)]);
        this.values.push([2, BufferHelper.hexToUint8Array(blockHash || ZERO_HASH)]);
        this.values.push([3, BufferHelper.hexToUint8Array(blockMerkleRoot || ZERO_HASH)]);
        this.values.push([4, BufferHelper.hexToUint8Array(blockStateRoot || ZERO_HASH)]);
        this.values.push([5, BufferHelper.hexToUint8Array(blockReceiptRoot || ZERO_HASH)]);

        this.generateTree();
    }

    public getProofs(): BlockHeaderChecksumProof {
        if (!this.tree) {
            throw new Error('Merkle tree not generated');
        }
        const result: BlockHeaderChecksumProof = []
        const hashes = this.tree.hashes()
        for (let i = 0; i < hashes.length; i++) {
            const hash = hashes[i]
            result.push([Number(i), this.tree.getProof(this.tree.getIndexHash(hash)).proofHashesHex()])
        }


        return result
    }

    private generateTree(): void {
        this.tree = new MerkleTree(this.values.map(v => ChecksumMerkleNew.toBytes(v)))
    }
}


test('Test ChecksumMerkle compatibility', (t) => {
    const merkleOld = new ChecksumMerkleOld()
    merkleOld.setBlockData(
        '0x6a1a20cf378c68b915be2d0f9a898f7006d874ce8ccf2a1d061ba688b3b8e8d1',
        '0x00000000000000000000c7430d04e6cce6e8f52e8d342528deb78fbf76939fe0',
        '0x000000000000000000003b485da71d761e3946459e33301e9227005014d32fe3',
        '0x000000000000000000020c661d8d78de9105a8d79a8fd8bc6b70e94a17762ef1',
        '0x0000000000000000000151f64e37678510ad013b25e6f4198c8fcb139079ca8c',
        '0x00000000000000000002e7eb918cbc3b0c30e7c924194d593d99949c334f89ea')
    const proofOld = merkleOld.getProofs()

    const merkleNew = new ChecksumMerkleNew()
    merkleNew.setBlockData(
        '0x6a1a20cf378c68b915be2d0f9a898f7006d874ce8ccf2a1d061ba688b3b8e8d1',
        '0x00000000000000000000c7430d04e6cce6e8f52e8d342528deb78fbf76939fe0',
        '0x000000000000000000003b485da71d761e3946459e33301e9227005014d32fe3',
        '0x000000000000000000020c661d8d78de9105a8d79a8fd8bc6b70e94a17762ef1',
        '0x0000000000000000000151f64e37678510ad013b25e6f4198c8fcb139079ca8c',
        '0x00000000000000000002e7eb918cbc3b0c30e7c924194d593d99949c334f89ea')
    const proofNew = merkleNew.getProofs()


    t.deepEqual(proofOld, proofNew)
    t.deepEqual(merkleOld!.root, merkleNew!.root)
    t.true(ChecksumMerkleOld.verify(merkleOld?.root!, ChecksumMerkleOld.TREE_TYPE, merkleOld?.values[0]!, proofOld![0][1]))
    t.true(new MerkleProof(proofOld![0][1].map(p => toBytes(p))).verify(toBytes(merkleNew?.root!), MerkleTree.hash(ChecksumMerkleNew.toBytes(merkleOld?.values[0]!))))
})
