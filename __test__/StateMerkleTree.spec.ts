import { randomAddress } from './generator.js';
import { StateMerkleTree } from './new/StateMerkleTreeNew.js';

const address1 = randomAddress();
const address2 = randomAddress();
const address3 = randomAddress();
const address4 = randomAddress();
const merkleNew = new StateMerkleTree();


merkleNew.updateValue(address1, 1n, 1n);
merkleNew.updateValue(address2, 2n, 2n);
merkleNew.updateValue(address3, 3n, 3n);
merkleNew.updateValue(address4, 4n, 4n);
merkleNew.generateTree();

const proofNew = merkleNew.getProofs();
console.log(proofNew);
console.assert(merkleNew.root, '0x5bc77dad33e9eb98b3c1800ea129ec5e9ec20afaacbdbcf110f21cb3e15da13c');
