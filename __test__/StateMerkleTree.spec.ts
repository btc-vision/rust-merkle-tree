import { expect, it } from 'vitest';

import { randomAddress } from './generator.js';
import { StateMerkleTree } from './new/StateMerkleTreeNew.js';

it('should generate a StateMerkleTree and produce proofs', () => {
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
    expect(merkleNew.root).toBeTruthy();
    expect(proofNew).toBeTruthy();
});
