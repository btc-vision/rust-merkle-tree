# Merkle Tree Design Explanation

This Merkle Tree implementation focuses on **double‐hashing leaves** (SHA‐256 applied twice) and **single‐hashing
internal nodes** (one SHA‐256 over concatenated child hashes).
Below is a conceptual walkthrough of how it works internally, including an example tree, how siblings come into play
(and why that matters), and how these design decisions enhance security and performance.

---

## 1. Core Concept of the Tree

A Merkle Tree is a binary tree of hashes:

- **Leaves** hold the hashed form of raw data (in this library, `SHA256(SHA256(data))`).
- **Internal nodes** each store a single SHA‐256 hash computed from *both* of their children's hashes.

By design, a **Merkle root** is the single hash at the top of the tree. Any change in any leaf propagates all the way to
the root, ensuring the root is a succinct fingerprint of the entire data set.

---

## 2. Example Merkle Tree & Siblings

To illustrate how siblings factor into verification, let’s consider a small tree with four leaves, named `A`, `B`, `C`,
and `D`. At the leaf level, each data block is hashed twice. We denote each leaf's double‐hash as `H(A)`, `H(B)`, etc.:

```
          R (root)
         /        \
       N1          N2
      /  \        /  \
    A     B      C    D
```

- **Leaf Nodes**: `A, B, C, D` (each storing `H(A), H(B), H(C), H(D)`).
- **Internal Nodes**:
    - `N1 = SHA256( concat( H(A), H(B) ) )`
    - `N2 = SHA256( concat( H(C), H(D) ) )`
- **Root**: `R = SHA256( concat( N1, N2 ) )`

### Sibling Pairs

In a **binary** Merkle Tree, each node has up to two children. Each child has a **sibling**: the other child of the same
parent. For instance:

- `A`’s sibling is `B`.
- `C`’s sibling is `D`.
- `N1`’s sibling is `N2`.

**Why Sibling Ordering Matters**

When combining two hashes, the order is *not interchangeable*—`SHA256(X||Y)` (concatenation of `X` then `Y`) is *not*
the same as `SHA256(Y||X)`. Our library stores a boolean `is_left` in each proof step to indicate whether the sibling is
on the left side or the right side. This ensures the *exact* hashing order is preserved during verification.

---

## 3. Merkle Proof and Sibling Direction

### Proof Steps

If you want to prove that leaf `B` is contained in the root `R`, you only need to reveal:

1. The hashed value of `B` (the leaf in question).
2. Each sibling **along the path** from `B` up to `R`.

In our example tree, that path would be:

1. `B`’s sibling is `A` (and `A` is on the **left**).
2. Then you move to their parent `N1`.  
   The sibling of `N1` is `N2` (on the **right**).
3. Hash all the way up to confirm you get `R`.

Hence the proof steps for `B` are:

- `(sibling_hash = H(A), is_left = true)`
- `(sibling_hash = N2, is_left = false)`

**Recomputing the Root**:

1. Since `is_left = true` for `A`, we do `SHA256( concat( A, B ) )` to get `N1`.
2. Then `N1`’s sibling is `N2` on the right, so we do `SHA256( concat( N1, N2 ) )`, yielding `R`.

If the final recomputed hash matches the **official** root, the proof is valid.

### Security Benefits of sibling direction

By storing `(sibling_hash, is_left)` for every step:

- **No Confusion of Order**: An attacker trying to reorder sibling pairs (e.g. `B, A` instead of `A, B`) will not
  reproduce the same parent hash.
- **Tamper Detection**: If *any* hash in the chain is changed or if the direction bit is flipped, the final computed
  root will be different from the original.

---

## 4. Advanced design features

1. **Direction‐Aware Siblings**  
   Many simpler designs omit an explicit "is_left" bit, relying on a strict rule about how siblings must be combined
   (e.g., always `minhash || maxhash`). That approach is more rigid and can lead to unexpected complexities or
   vulnerabilities if the combination logic is misunderstood. Explicit flags make the proof steps **self‐describing**
   and unambiguous.

2. **Parallel Construction**  
   Internally, this tree uses concurrency (via [Rayon](https://crates.io/crates/rayon)) to handle large numbers of
   leaves efficiently. Many older designs rely on sequential building.

3. **Immutable + Array‐Based**  
   The array layout is straightforward for indexing parent/sibling with zero overhead beyond integer arithmetic (no
   pointer chasing). It also helps avoid complexities of a pointer‐based tree structure. In bigger codebases, an array
   approach typically outperforms node‐per‐object models.

4. **Consistency with Bitcoin**  
   Using double‐SHA256 for leaves plus single‐SHA256 for internal nodes aligns with the Bitcoin transaction Merkle tree
   standard. If you rely on or integrate with Bitcoin’s logic or tooling, this design is highly compatible.

---

## 5. Detailed Tree Example With Siblings

Below is a more expanded scenario with leaves `A`, `B`, `C`, `D`:

1. **Leaf Hashes**:
    - `A' = SHA256(SHA256(A))`
    - `B' = SHA256(SHA256(B))`
    - `C' = SHA256(SHA256(C))`
    - `D' = SHA256(SHA256(D))`

2. **Parent Nodes**:
    - `N1 = SHA256( A' || B' )`
    - `N2 = SHA256( C' || D' )`

3. **Root**:
    - `R = SHA256( N1 || N2 )`

To prove membership of leaf `C`, the proof steps are:

1. `(sibling_hash = D', is_left = false)`  
   Because `C'` is the left child, and `D'` is the right child, so the sibling is "on the right."
2. `(sibling_hash = N1, is_left = true)`  
   Because `N2` is the right subtree, so from the perspective of `N2`, the sibling node is `N1` on the left.

**Verification**:

- Start `current = C'`.
- Step 1: `is_left = false` => `current = SHA256( current || D' )` => produces `N2`.
- Step 2: `is_left = true` => `current = SHA256( N1 || current )` => produces `R`.

If this final `current` equals the known root `R`, it’s valid. If you swap the order anywhere (`D' || current` vs.
`current || D'`) or change the direction bit, the final hash won’t match the real root.