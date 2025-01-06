import test from 'ava';
import { randomAddress } from './generator.js';
import { StateMerkleTreeNew } from './new/StateMerkleTreeNew.js';
import { MerkleProof } from '../index.js';

test('Test StateMerkleTree compatibility', (t) => {
    const address1 = randomAddress();
    const address2 = randomAddress();
    const address3 = randomAddress();
    const address4 = randomAddress();
    const merkleNew = new StateMerkleTreeNew();


    merkleNew.updateValue(address1, 1n, 1n);
    merkleNew.updateValue(address2, 2n, 2n);
    merkleNew.updateValue(address3, 3n, 3n);
    merkleNew.updateValue(address4, 4n, 4n);
    merkleNew.generateTree();

    const proofNew = merkleNew.getProofs();

    t.assert(merkleNew.root, "0x5bc77dad33e9eb98b3c1800ea129ec5e9ec20afaacbdbcf110f21cb3e15da13c")
});
