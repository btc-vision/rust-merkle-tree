import test from 'ava';

import { StandardMerkleTree } from '@btc-vision/merkle-tree';
import { MerkleTree } from '../index.js';
import { defaultAbiCoder } from '@ethersproject/abi';
import { arrayify as toBytes } from '@ethersproject/bytes';

function objToBytes(value: any): Uint8Array {
    const data = defaultAbiCoder.encode(['string'], value);
    return toBytes(data);
}

test('Test Performance compatibility', (t) => {
    let oldPerf = 0;
    let newPerf = 0;
    let now = 0;

    for (let i = 2; i < 2 ** 14; i *= 2) {
        const data: [string][] = Array.from(Array(i).keys()).map((n) => [String(n)]);
        now = performance.now();
        const oldTree = StandardMerkleTree.of<[string]>(data, ['string'], { sortLeaves: true });
        oldPerf += performance.now() - now;

        now = performance.now();
        const newTree = new MerkleTree(
            data.map((d) => objToBytes(d))
        );
        newPerf += performance.now() - now;

        t.assert(oldTree.root, newTree.rootHex());

        for (let d of data) {
            now = performance.now();
            const oldProof = oldTree.getProof(oldTree.leafLookup(d));
            const oldPerfDiff = performance.now() - now;
            oldPerf += oldPerfDiff;

            now = performance.now();
            const newProof = newTree.getProof(newTree.getIndexData(objToBytes(d))).proofHashesHex();
            const newPerfDiff = performance.now() - now;
            newPerf += newPerfDiff;
        }
    }

    console.log('Performance data lookup: ', newPerf, oldPerf);
    t.assert(newPerf < oldPerf);
});

test('Test Performance compatibility indexed', (t) => {
    let oldPerf = 0;
    let newPerf = 0;
    let now = 0;

    for (let i = 2; i < 2 ** 14; i *= 2) {
        const data: [string][] = Array.from(Array(i).keys()).map((n) => [String(n)]);
        now = performance.now();
        const oldTree = StandardMerkleTree.of<[string]>(data, ['string'], { sortLeaves: true });
        oldPerf += performance.now() - now;

        now = performance.now();
        const newTree = new MerkleTree(
            data.map((d) => objToBytes(d)),
        );
        newPerf += performance.now() - now;

        t.assert(oldTree.root, newTree.rootHex());

        for (let i = 0; i < data.length; i++) {
            now = performance.now();
            const oldProof = oldTree.getProof(i);
            const oldPerfDiff = performance.now() - now;
            oldPerf += oldPerfDiff;

            now = performance.now();
            const newProof = newTree.getProof(i).proofHashesHex();
            const newPerfDiff = performance.now() - now;
            newPerf += newPerfDiff;
        }
    }

    console.log('Performance indexed: ', newPerf, oldPerf);
    t.assert(newPerf < oldPerf);
});

test('Test Performance', (t) => {
    let oldPerf = 0;
    let newPerf = 0;
    let now = 0;

    for (let i = 2; i < 2 ** 14; i *= 2) {
        const data: [string][] = Array.from(Array(i).keys()).map((n) => [String(n)]);
        now = performance.now();
        const oldTree = StandardMerkleTree.of<[string]>(data, ['string'], { sortLeaves: true });
        oldPerf += performance.now() - now;

        now = performance.now();
        const newTree = new MerkleTree(
            data.map((d) => objToBytes(d)),
        );
        newPerf += performance.now() - now;

        const a = Date.now();
        const hashes = newTree.hashes();
        console.log('Hashes: ', Date.now() - a + 'ms');

        const proofs = [];

        const start = Date.now();
        for (let i = 0; i < hashes.length; i++) {
            const hash = hashes[i];
            proofs.push(newTree.getProof(newTree.getIndexHash(hash)).proofHashesHex());
        }
        console.log('Proofs: ', Date.now() - start + 'ms');

        t.assert(oldTree.root, newTree.rootHex());
    }

    console.log('Performance building: ', newPerf, oldPerf);
    t.assert(newPerf < oldPerf);
});
