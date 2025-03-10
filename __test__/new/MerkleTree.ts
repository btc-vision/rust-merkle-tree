import { Address, AddressMap } from '@btc-vision/transaction';
import { BTC_FAKE_ADDRESS } from '../types/ZeroValue.js';
import { MerkleTree as RustMerkleTree, safeInitRust } from '../../index.js';

safeInitRust();

export function toBytes(bytesStr: string): Buffer {
    return Buffer.from(bytesStr.replace('0x', ''), 'hex');
}

export abstract class MerkleTree<K, V> {
    public static readonly DUMMY_ADDRESS_NON_EXISTENT: Address = BTC_FAKE_ADDRESS;

    public readonly values: AddressMap<Map<K, V>> = new AddressMap();

    protected valueChanged: boolean = false;
    protected frozen: boolean = false;

    private readonly MINIMUM_VALUES = 2; // To generate a tree, we need at least 2 values

    public get root(): string {
        return this.tree.rootHex();
    }

    protected _tree: RustMerkleTree | undefined;

    private get tree(): RustMerkleTree {
        if (!this._tree) {
            throw new Error('Merkle tree not generated');
        }

        return this._tree;
    }

    public abstract toBytes(value: unknown[]): Uint8Array;

    public getProofHashes(data: Buffer[]): Array<string> {
        return this.tree.getProof(this.tree.getIndexData(this.toBytes(data))).proofHashesHex();
    }

    public size(): number {
        return this.values.size;
    }

    public abstract getValue(address: Address, key: K): V | undefined;

    public abstract getValueWithProofs(
        address: Address,
        key: K,
    ): [V | Uint8Array, string[]] | undefined;

    public hasTree(): boolean {
        return !!this._tree;
    }

    public generateTree(regeneratedIfValueChanged: boolean = true): void {
        if (this.frozen) {
            throw new Error('Merkle tree is frozen');
        }

        if (!this.values.size) {
            return;
        }

        if (this._tree && !this.valueChanged && !regeneratedIfValueChanged) {
            return;
        }

        const values = this.getValues();
        this._tree = new RustMerkleTree(values.map((l) => this.toBytes(l)));

        this.valueChanged = false;
    }

    public abstract getValuesWithProofs(address: Address): Map<K, [V, string[]]>;

    public abstract getEverythingWithProofs(): AddressMap<Map<K, [V, string[]]>> | undefined;

    public freeze(): void {
        if (this.countValues() < this.MINIMUM_VALUES) {
            // We will add two empty values to generate the tree

            const dummyValues = this.getDummyValues();
            for (const [address, map] of dummyValues) {
                if (!this.values.has(address)) {
                    this.values.set(address, map);
                } else {
                    const currentMap = this.values.get(address);
                    if (!currentMap) {
                        throw new Error('Map not found');
                    }

                    for (const [key, value] of map) {
                        if (!currentMap.has(key)) {
                            currentMap.set(key, value);
                        }
                    }
                }
            }
        }

        this.generateTree();

        this.frozen = true;
    }

    public abstract getProofs(): AddressMap<Map<K, string[]>>;

    public abstract updateValue(address: Address, key: K, val: V): void;

    public abstract updateValues(address: Address, val: Map<K, V>): void;

    public abstract getValues(): [Buffer, Buffer][];

    protected abstract getDummyValues(): AddressMap<Map<K, V>>;

    private countValues(): number {
        let count = 0;
        for (const [, map] of this.values) {
            count += map.size;
        }

        return count;
    }
}
