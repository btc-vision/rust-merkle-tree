import test from 'ava';
import { randomAddress } from './generator.js';
import { ReceiptMerkleTree } from './new/ReceiptMerkleTreeNew.js';

test('Test ReceiptMerkleTree compatibility', (t) => {
    const contract = randomAddress();
    const transactionId1 = '0xaaa0';
    const transactionId2 = '0xaaab';
    const transactionId3 = '0xaaac';
    const transactionId4 = '0xaaad';
    const transactionId5 = '0xaaae';
    const transactionId6 = '0xaaaf';
    const transactionId7 = '0xaaa1';
    const transactionId8 = '0xaaa2';

    const merkleNew = new ReceiptMerkleTree();


    merkleNew.updateValue(contract, transactionId1, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    merkleNew.updateValue(contract, transactionId2, new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9]));
    merkleNew.updateValue(contract, transactionId3, new Uint8Array([4, 5, 6, 7, 8, 9, 10, 11]));
    merkleNew.updateValue(contract, transactionId4, new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12]));
    merkleNew.updateValue(contract, transactionId5, new Uint8Array([6, 7, 8, 9, 10, 11, 12, 13]));
    merkleNew.updateValue(contract, transactionId6, new Uint8Array([7, 8, 9, 10, 11, 12, 13, 14]));
    merkleNew.updateValue(contract, transactionId7, new Uint8Array([8, 9, 10, 11, 12, 13, 14, 15]));
    merkleNew.updateValue(
        contract,
        transactionId8,
        new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]),
    );

    merkleNew.generateTree();

    const proofNew = merkleNew.getProofs();
    t.assert(merkleNew.root, '0x6c076f64d7eeb641a2d410614415c75fbfb06b58903e7d902dd2c2fc2dce12c6');
});
