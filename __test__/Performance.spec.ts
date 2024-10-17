import { StandardMerkleTree } from '@btc-vision/merkle-tree'
import { MerkleTree, MerkleProof } from '..'
import { defaultAbiCoder } from '@ethersproject/abi'
import { arrayify as toBytes } from '@ethersproject/bytes'
import test from 'ava'

function objToBytes(value: any): Uint8Array {
    const data = defaultAbiCoder.encode(['string'], value)
    const result = toBytes(data)
    return result
}


test('Test Performance compatibility', (t) => {
    let oldPerf = 0
    let newPerf = 0
    let now = 0

    for (let i = 2; i < 2 ** 14; i *= 2) {
        const data: [string][] = Array.from(Array(i).keys()).map(n => [String(n)])
        now = performance.now()
        const oldTree = StandardMerkleTree.of<[string]>(data, ['string'], { sortLeaves: true })
        oldPerf += performance.now() - now

        now = performance.now()
        const newTree = new MerkleTree(data.map(d => objToBytes(d)), true)
        newPerf += performance.now() - now

        t.assert(oldTree.root, newTree.rootHex())

        for (let d of data) {
            now = performance.now()
            const oldProof = oldTree.getProof(oldTree.leafLookup(d))
            const oldPerfDiff = performance.now() - now
            oldPerf += oldPerfDiff

            now = performance.now()
            const newProof = newTree.getProof(newTree.getIndexData(objToBytes(d))).proofHashesHex()
            const newPerfDiff = performance.now() - now
            newPerf += newPerfDiff

            //console.log("NEW: ", newPerf)

            console.log("Perf: ", i, newPerfDiff, oldPerfDiff)
            t.deepEqual(oldProof, newProof)
        }
    }

    console.log("Perf: ", newPerf, oldPerf)
    t.assert(newPerf < oldPerf)
})
