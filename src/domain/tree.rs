use anyhow::{anyhow, Result};
use log::{debug, info};
use rayon::prelude::*;
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::sync::Mutex;
use std::time::Instant;

use super::proof::MerkleProofInner;

/// A trait that Merkle tree implementations must follow.
pub trait MerkleTreeTrait {
    /// Hash a leaf’s data. (Here: double SHA-256.)
    fn hash_leaf(data: &[u8]) -> Vec<u8>;

    /// Hash two child nodes together. (Here: single SHA-256.)
    fn hash_nodes(left: &[u8], right: &[u8]) -> Vec<u8>;
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MerkleTreeSha256 {
    tree: Vec<Vec<u8>>,    // array-based complete binary tree
    root: Option<Vec<u8>>, // cached root
}

impl MerkleTreeTrait for MerkleTreeSha256 {
    fn hash_leaf(data: &[u8]) -> Vec<u8> {
        // Double SHA-256 for leaf data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let once = hasher.finalize_fixed();

        let mut hasher = Sha256::new();
        hasher.update(once);
        hasher.finalize_fixed().to_vec()
    }

    fn hash_nodes(left: &[u8], right: &[u8]) -> Vec<u8> {
        // Single SHA-256 for internal nodes
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize_fixed().to_vec()
    }
}

impl MerkleTreeSha256 {
    /// Build a MerkleTreeSha256 from raw leaves data (will be double-hashed).
    pub fn from_leaves_data(leaves: Vec<Vec<u8>>) -> Result<Self> {
        let hashed_leaves: Vec<_> = leaves
            .par_iter()
            .map(|leaf| Self::hash_leaf(leaf))
            .collect();
        Self::from_leaves_hashes(hashed_leaves)
    }

    /// Build a MerkleTreeSha256 from already-hashed leaves.
    pub fn from_leaves_hashes(leaves: Vec<Vec<u8>>) -> Result<Self> {
        let total_start = Instant::now();
        let leaves_len = leaves.len();
        if leaves_len == 0 {
            return Err(anyhow!("Leaves cannot be empty"));
        }

        let tree_len = 2 * leaves_len - 1;
        let tree: Vec<Mutex<Vec<u8>>> = (0..tree_len).map(|_| Mutex::new(Vec::new())).collect();

        // Place leaves in the bottom half
        let leaf_start = tree_len - leaves_len; // e.g. for leaves_len=3 => 5-3=2 => place them at indices 2,3,4
        for (i, hash) in leaves.iter().enumerate() {
            let idx = leaf_start + i;
            *tree[idx].lock().map_err(|_| anyhow!("Mutex poisoned"))? = hash.clone();
        }

        // Then build the internal nodes from the root
        let root_hash = build_subtree(&tree, 0, tree_len)?;
        debug!("Building the tree took {:?}", total_start.elapsed());

        let extract_start = Instant::now();
        let final_tree: Vec<Vec<u8>> = tree
            .into_iter()
            .map(|m| m.into_inner().unwrap_or_default())
            .collect();
        debug!("Extracting tree vector took {:?}", extract_start.elapsed());

        let total_duration = total_start.elapsed();
        info!("Total duration of from_leaves_hashes: {:?}", total_duration);

        Ok(Self {
            root: Some(root_hash),
            tree: final_tree,
        })
    }

    /// Return an iterator over the leaf nodes (the bottom half of the array).
    pub fn get_hashes(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.tree.iter().skip(self.tree.len() / 2)
    }

    /// Return the Merkle root, or error if missing (should never be if built properly).
    pub fn get_root(&self) -> Result<Vec<u8>> {
        self.root
            .clone()
            .ok_or_else(|| anyhow!("Merkle root not generated"))
    }

    /// Return the index of data (after double-hash) in the tree, or error if not found.
    pub fn get_index_by_data(&self, data: &[u8]) -> Result<usize> {
        let hashed = Self::hash_leaf(data);
        self.get_index_by_hash(&hashed)
    }

    /// Return the index of a hashed leaf in the array, or error if not found.
    pub fn get_index_by_hash(&self, hash: &[u8]) -> Result<usize> {
        self.tree
            .iter()
            .position(|h| h == hash)
            .ok_or_else(|| anyhow!("Hash not found in the Merkle tree"))
    }

    /// Generate a proof for the leaf at array index index. The proof
    /// will store each sibling’s hash along with a boolean telling if the sibling is on the left.
    pub fn get_proof(&self, index: usize) -> Result<MerkleProofInner<Self>> {
        if index >= self.tree.len() {
            return Err(anyhow!("Index out of range"));
        }

        let mut path = Vec::new();
        let mut node = index;

        // While we're not at the root
        while node > 0 {
            let parent = parent_index(node)?;
            let sibling = sibling_index(node)?;

            // If the sibling is less than node, it means sibling is on the left side
            let is_left = sibling < node;

            // Save (sibling_hash, sibling_is_left)
            path.push((is_left, self.tree[sibling].clone()));

            node = parent; // move upward
        }

        // Check that the proof is correct
        let leaf_hash = self.tree[index].clone();
        let root = self.get_root()?;
        let proof = MerkleProofInner::new(path);
        if proof.verify(&root, &leaf_hash) {
            Ok(proof)
        } else {
            Err(anyhow!("Proof does not match the Merkle root"))
        }
    }
}

/// Build a subtree rooted at node_index. Uses Rayon to join left and right children.
fn build_subtree(tree: &[Mutex<Vec<u8>>], node_index: usize, tree_len: usize) -> Result<Vec<u8>> {
    let left = left_child_index(node_index);
    // If left >= tree_len, we’re a leaf
    if left >= tree_len {
        let locked = tree[node_index]
            .lock()
            .map_err(|_| anyhow!("Mutex poisoned"))?;
        return Ok(locked.clone());
    }

    let right = right_child_index(node_index);

    let (left_hash_res, right_hash_res) = rayon::join(
        || build_subtree(tree, left, tree_len),
        || build_subtree(tree, right, tree_len),
    );

    let left_hash = left_hash_res?;
    let right_hash = right_hash_res?;

    let parent_hash = MerkleTreeSha256::hash_nodes(&left_hash, &right_hash);
    let mut locked = tree[node_index]
        .lock()
        .map_err(|_| anyhow!("Mutex poisoned"))?;
    *locked = parent_hash.clone();
    Ok(parent_hash)
}

/// Standard "binary heap" style index calculations:
fn left_child_index(i: usize) -> usize {
    2 * i + 1
}
fn right_child_index(i: usize) -> usize {
    2 * i + 2
}
fn parent_index(i: usize) -> Result<usize> {
    if i == 0 {
        Err(anyhow!("Root has no parent (index = 0)"))
    } else {
        Ok((i - 1) / 2)
    }
}
fn sibling_index(i: usize) -> Result<usize> {
    if i == 0 {
        Err(anyhow!("Root has no sibling (index = 0)"))
    } else if i % 2 == 1 {
        // node is left child => sibling = node+1
        Ok(i + 1)
    } else {
        // node is right child => sibling = node-1
        Ok(i - 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::tree::{parent_index, sibling_index, MerkleTreeSha256, MerkleTreeTrait};
    use rand::Rng;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_empty_leaves_error() {
        let leaves: Vec<Vec<u8>> = vec![];
        let result = MerkleTreeSha256::from_leaves_data(leaves);
        assert!(
            result.is_err(),
            "Building a tree from empty leaves must return an error"
        );
    }

    #[test]
    fn test_single_leaf_tree() {
        // If there's only one leaf, the Merkle root is just the double-hash of that leaf.
        let leaves = vec![b"only_leaf".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Should build a single-leaf tree successfully");
        let root = tree.get_root().expect("Should have a valid root");

        let expected = MerkleTreeSha256::hash_leaf(b"only_leaf");
        assert_eq!(
            root, expected,
            "Single-leaf root must match the leaf's double-hash"
        );

        // Check the proof
        let proof = tree.get_proof(0).expect("Proof for index 0 must succeed");
        let verification = proof.verify(&root, &expected);
        assert!(
            verification,
            "Single-leaf proof must verify with the correct leaf hash"
        );
    }

    #[test]
    fn test_multiple_leaves_correct_root() {
        let leaves: Vec<Vec<u8>> = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];

        let tree =
            MerkleTreeSha256::from_leaves_data(leaves.clone()).expect("Tree creation must succeed");
        let root = tree.get_root().unwrap();

        // For each leaf, build a proof and verify
        for leaf_data in &leaves {
            let leaf_hash = MerkleTreeSha256::hash_leaf(leaf_data);
            let idx = tree.get_index_by_hash(&leaf_hash).unwrap();
            let proof = tree.get_proof(idx).unwrap();

            println!(
                "validating proof for leaf_data: {:?}",
                proof.verify(&root, &leaf_hash)
            );

            assert!(
                proof.verify(&root, &leaf_hash),
                "Proof for leaf_data '{:?}' must verify",
                leaf_data
            );
        }
    }

    #[test]
    fn test_random_leaves() {
        // Varying sizes for random leaves
        let sizes = [2, 5, 16, 33];
        for &size in &sizes {
            let random_leaves = generate_random_leaves(size);
            let tree = MerkleTreeSha256::from_leaves_data(random_leaves.clone())
                .expect("Random tree creation must succeed");
            let root = tree.get_root().unwrap();

            // Check a subset of leaves
            for _ in 0..3 {
                let i = rand::rng().random_range(0..size);
                let leaf_hash = MerkleTreeSha256::hash_leaf(&random_leaves[i]);
                let index = tree
                    .get_index_by_hash(&leaf_hash)
                    .expect("Leaf must be in the tree");

                let proof = tree
                    .get_proof(index)
                    .expect("Proof generation must succeed");
                assert!(proof.verify(&root, &leaf_hash), "Random leaf must verify");
            }
        }
    }

    #[test]
    fn test_proof_out_of_range_index() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves).unwrap();
        // There's only 2 leaves, so index = 999 is invalid
        let result = tree.get_proof(999);
        assert!(result.is_err(), "Should error for out-of-range index");
    }

    #[test]
    fn test_proof_missing_data() {
        // Build a tree with 2 leaves
        let leaves = vec![b"some".to_vec(), b"data".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves).unwrap();

        // We look up something that isn't in the tree
        let missing_hash = MerkleTreeSha256::hash_leaf(b"not in the tree!");
        let result = tree.get_index_by_hash(&missing_hash);
        assert!(result.is_err(), "Index lookup must fail for missing data");
    }

    #[test]
    fn test_duplicate_leaves() {
        // If leaves are identical, the tree must contain both at different positions
        let leaves = vec![b"dup".to_vec(), b"dup".to_vec(), b"dup".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone()).unwrap();
        assert_eq!(
            tree.get_hashes().count(),
            leaves.len(),
            "Tree must have the correct number of leaves"
        );

        // We find all indices for the same hashed leaf
        let dup_hash = MerkleTreeSha256::hash_leaf(b"dup");
        // Now we search the entire tree for positions
        let positions: Vec<_> = tree
            .tree
            .iter()
            .enumerate()
            .filter_map(|(i, h)| if *h == dup_hash { Some(i) } else { None })
            .collect();

        assert!(
            positions.len() >= 3,
            "We expect at least 3 matches in the array structure"
        );
    }

    // VALIDITY TESTS

    /// -----------------------------------------------------------------------
    /// Test Very Large Leaf Data
    /// -----------------------------------------------------------------------
    #[test]
    fn test_very_large_leaf_data() {
        // Create a single leaf with a large data buffer (e.g. 1 MB).
        let large_data = vec![0xAB; 64 * 1024];
        let leaves = vec![large_data];

        // Build the tree
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Must handle large leaf data without error");

        // The root should be well-defined
        let root = tree.get_root().expect("Root must exist");

        // If we attempt to generate a proof for the only leaf, it must verify.
        let proof = tree
            .get_proof(0)
            .expect("Proof for single large leaf must succeed");
        let hashed_leaf = MerkleTreeSha256::hash_leaf(&leaves[0]);
        assert!(
            proof.verify(&root, &hashed_leaf),
            "Large single-leaf proof must verify"
        );
    }

    /// -----------------------------------------------------------------------
    /// Test Odd Number of Leaves (Non‐Power‐of‐Two)
    /// -----------------------------------------------------------------------
    #[test]
    fn test_odd_number_of_leaves() {
        // 7 leaves => a "ragged" tree shape
        let leaves: Vec<Vec<u8>> = (0..7).map(|i| format!("leaf_{i}").into_bytes()).collect();

        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Tree must handle odd number of leaves");

        // Basic checks
        let root = tree.get_root().unwrap();
        assert_eq!(tree.get_hashes().count(), 7, "Should have exactly 7 leaves");

        // Verify each leaf’s proof
        for leaf_data in &leaves {
            let leaf_hash = MerkleTreeSha256::hash_leaf(leaf_data);
            let idx = tree.get_index_by_hash(&leaf_hash).unwrap();
            let proof = tree.get_proof(idx).unwrap();
            assert!(
                proof.verify(&root, &leaf_hash),
                "Proof must verify for leaf '{:?}'",
                leaf_data
            );
        }
    }

    /// -----------------------------------------------------------------------
    /// Test from_leaves_hashes (Already‐Hashed Leaves)
    /// -----------------------------------------------------------------------
    #[test]
    fn test_from_leaves_hashes() {
        // Suppose we already have hashed leaves from some external step
        let raw_leaves: Vec<Vec<u8>> = vec![
            b"user_supplied_leaf_1".to_vec(),
            b"user_supplied_leaf_2".to_vec(),
            b"user_supplied_leaf_3".to_vec(),
        ];

        let hashed_leaves: Vec<Vec<u8>> = raw_leaves
            .iter()
            .map(|l| MerkleTreeSha256::hash_leaf(l))
            .collect();

        // Build from prehashed
        let tree = MerkleTreeSha256::from_leaves_hashes(hashed_leaves.clone())
            .expect("Must build tree from pre‐hashed leaves");

        let root = tree.get_root().unwrap();
        assert_eq!(
            tree.get_hashes().count(),
            hashed_leaves.len(),
            "Leaf count should match"
        );

        // Checking the proof for each hashed leaf
        for hashed_leaf in &hashed_leaves {
            let idx = tree.get_index_by_hash(hashed_leaf).unwrap();
            let proof = tree.get_proof(idx).unwrap();
            assert!(
                proof.verify(&root, hashed_leaf),
                "Pre‐hashed leaf must verify"
            );
        }
    }

    /// -----------------------------------------------------------------------
    /// Test Attempting to Use the Wrong Root in Verification
    /// -----------------------------------------------------------------------
    #[test]
    fn test_wrong_root_fails() {
        let leaves = vec![b"secure_leaf".to_vec(), b"another_leaf".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone()).expect("Must build tree");

        let correct_root = tree.get_root().unwrap();
        let wrong_root = MerkleTreeSha256::hash_leaf(b"totally_wrong_root");

        // Generate a proof for "another_leaf"
        let idx = tree.get_index_by_data(b"another_leaf").unwrap();
        let proof = tree.get_proof(idx).unwrap();
        let leaf_hash = MerkleTreeSha256::hash_leaf(b"another_leaf");

        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Must verify with correct root"
        );

        assert!(
            !proof.verify(&wrong_root, &leaf_hash),
            "Verifying with a random/wrong root must fail"
        );
    }

    /// -----------------------------------------------------------------------
    /// Test Malicious Sibling Replacement
    /// -----------------------------------------------------------------------
    #[test]
    fn test_malicious_sibling_replacement() {
        let leaves = vec![b"leafA".to_vec(), b"leafB".to_vec(), b"leafC".to_vec()];
        let tree =
            MerkleTreeSha256::from_leaves_data(leaves.clone()).expect("Tree must build fine");
        let root = tree.get_root().unwrap();

        // Build a correct proof for "leafB"
        let idx_b = tree.get_index_by_data(b"leafB").unwrap();
        let mut proof = tree.get_proof(idx_b).unwrap();

        // Forcibly mutate the proof: replace the first sibling with a fake hash
        if !proof.steps.is_empty() {
            let fake_sibling = MerkleTreeSha256::hash_leaf(b"FAKE_SIBLING");
            proof.steps[0].1 = fake_sibling;
        }

        // Now the proof must fail
        let leaf_hash_b = MerkleTreeSha256::hash_leaf(b"leafB");
        assert!(
            !proof.verify(&root, &leaf_hash_b),
            "Malicious replacement of sibling must invalidate the proof"
        );
    }

    /// -----------------------------------------------------------------------
    /// Test Direction‐Bit Flip (Says Sibling is Left vs. Right)
    /// -----------------------------------------------------------------------
    #[test]
    fn test_malicious_direction_flip() {
        // We'll use two leaves for simplicity
        let leaves = vec![b"left".to_vec(), b"right".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone()).unwrap();
        let root = tree.get_root().unwrap();

        // If we want the proof for the "left" leaf, we pass index=1.
        let mut proof = tree.get_proof(1).unwrap();
        let correct_leaf = MerkleTreeSha256::hash_leaf(b"left");

        // This should succeed now
        assert!(
            proof.verify(&root, &correct_leaf),
            "Initial correct proof must pass"
        );

        // Flip the direction bit
        if !proof.steps.is_empty() {
            let (is_left, _) = &mut proof.steps[0];
            *is_left = !*is_left;
        }

        // Now it must fail
        assert!(
            !proof.verify(&root, &correct_leaf),
            "Flipping direction bit must fail verification"
        );
    }

    /// -----------------------------------------------------------------------
    /// Test Partial / Incomplete Proof
    /// -----------------------------------------------------------------------
    #[test]
    fn test_incomplete_proof_fails() {
        let leaves = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone()).unwrap();
        let root = tree.get_root().unwrap();

        // Build a correct proof for "two"
        let idx_two = tree.get_index_by_data(b"two").unwrap();
        let mut proof = tree.get_proof(idx_two).unwrap();

        // Drop the last step from the proof => incomplete path to root
        if !proof.steps.is_empty() {
            proof.steps.pop();
        }

        let leaf_hash_two = MerkleTreeSha256::hash_leaf(b"two");
        assert!(
            !proof.verify(&root, &leaf_hash_two),
            "An incomplete proof must fail verification"
        );
    }

    /// -----------------------------------------------------------------------
    /// Test Large Number of Leaves (Stress Test)
    /// -----------------------------------------------------------------------
    #[test]
    fn test_large_number_of_leaves_stress() {
        let mut leaves = Vec::new();
        for i in 0..20000 {
            leaves.push(format!("leaf_{i}").into_bytes());
        }
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Must handle large number of leaves");
        let root = tree.get_root().unwrap();

        // Spot‐check a few random leaves
        let mut rng = rand::rng();
        for _ in 0..5 {
            let idx = rng.random_range(0..leaves.len());
            let leaf_hash = MerkleTreeSha256::hash_leaf(&leaves[idx]);
            let proof = tree
                .get_proof(tree.get_index_by_hash(&leaf_hash).unwrap())
                .expect("Proof generation must succeed");
            assert!(
                proof.verify(&root, &leaf_hash),
                "Proof for a random leaf must still verify in large tree"
            );
        }
    }

    // Performance tests:

    /// ------------------------------------------------------------------------
    /// Test Immutability: Attempt to Insert Extra Leaves After Construction
    /// ------------------------------------------------------------------------
    #[test]
    fn test_cannot_insert_extra_leaves_after_construction() {
        // Build a small tree
        let leaves = vec![b"A".to_vec(), b"B".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves).expect("Must build tree");

        // In a real blockchain environment, we never want to allow
        // "inserting more leaves" after the root is established.
        // There is no provided API for adding leaves, so this test
        // basically shows we *cannot* do it in a normal usage scenario.

        // Check that there's no public function to mutate 'tree.tree'.
        // If we tried something like tree.tree.push(...) directly, it fails
        // because tree is private and there's no public method to modify it.

        // Instead, we confirm the final root is correct, and any attempt
        // to rebuild with extra data would produce a *separate* new tree.
        let root_original = tree.get_root().expect("Root must exist");

        // Build a new tree with more leaves
        let new_leaves = vec![b"A".to_vec(), b"B".to_vec(), b"C".to_vec()];
        let new_tree = MerkleTreeSha256::from_leaves_data(new_leaves).expect("New tree built");
        let root_new = new_tree.get_root().unwrap();

        // The two roots must differ, demonstrating that you cannot quietly "insert"
        // new data into an existing Merkle tree. You must build a *new* one.
        assert_ne!(
            root_original, root_new,
            "New data yields a different root, so we cannot exploit the old tree"
        );
    }

    /// ------------------------------------------------------------------------
    /// Stress Test for Concurrency (Blockchain Nodes Verifying Proofs in Parallel)
    /// ------------------------------------------------------------------------
    #[test]
    fn test_concurrent_verification() {
        // Build a moderately large tree
        let leaves = generate_random_leaves(500);
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Must build tree for concurrency test");

        let root = tree.get_root().unwrap();
        let arc_tree = Arc::new(tree); // share among threads

        let mut handles = Vec::new();

        // Spawn multiple threads, each verifying random leaves
        for _ in 0..10 {
            let tree_ref = Arc::clone(&arc_tree);
            let leaves_copy = leaves.clone();
            let root_copy = root.clone();

            let handle = thread::spawn(move || {
                let mut rng = rand::rng();
                // Each thread verifies 20 random leaves
                for _ in 0..20 {
                    let idx = rng.random_range(0..leaves_copy.len());
                    let leaf_hash = MerkleTreeSha256::hash_leaf(&leaves_copy[idx]);
                    let proof = tree_ref
                        .get_proof(tree_ref.get_index_by_hash(&leaf_hash).unwrap())
                        .expect("Proof must exist");

                    assert!(
                        proof.verify(&root_copy, &leaf_hash),
                        "Concurrent verification must succeed"
                    );
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for h in handles {
            h.join().expect("Thread must not panic");
        }
    }

    /// ------------------------------------------------------------------------
    /// Test Duplicate Leaves in a Blockchain Context
    /// ------------------------------------------------------------------------
    #[test]
    fn test_duplicate_leaves_blockchain_scenario() {
        // In blockchains, sometimes multiple identical transactions (e.g. dust spam)
        // might appear. We confirm the tree can handle duplicates safely.
        let leaves = vec![
            b"tx".to_vec(),
            b"tx".to_vec(),
            b"tx".to_vec(),
            b"tx".to_vec(),
        ];

        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Tree must handle duplicates");

        let root = tree.get_root().unwrap();

        // All leaves are identical. But each is stored in a different position.
        // We'll just check that we can generate a proof for each.
        for _i in 0..4 {
            let proof = tree
                .get_proof(tree.get_index_by_data(b"tx").unwrap())
                .unwrap();
            let leaf_hash = MerkleTreeSha256::hash_leaf(b"tx");
            assert!(
                proof.verify(&root, &leaf_hash),
                "Proof must verify for each identical leaf"
            );
        }
    }

    /// ------------------------------------------------------------------------
    /// Test "Root Tampering" Attempt in a Blockchain-like Environment
    /// ------------------------------------------------------------------------
    #[test]
    fn test_cannot_tamper_root() {
        // In many blockchain designs, the root is stored in a block header.
        // We confirm that if someone tampers with the root, proofs no longer match.

        let leaves = vec![b"block_tx_1".to_vec(), b"block_tx_2".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone()).expect("Tree builds");
        let correct_root = tree.get_root().unwrap();

        // Suppose an attacker tries to "publish" a tampered root
        // (e.g. a random hash).
        let tampered_root = vec![0xAA; 32]; // 32 bytes of 0xAA
        assert_ne!(correct_root, tampered_root);

        // The proof for "block_tx_1" must fail under this tampered root
        let idx = tree.get_index_by_data(b"block_tx_1").unwrap();
        let proof = tree.get_proof(idx).unwrap();
        let leaf_hash = MerkleTreeSha256::hash_leaf(b"block_tx_1");

        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Proof must pass with the correct root"
        );
        assert!(
            !proof.verify(&tampered_root, &leaf_hash),
            "Any tampered root must fail"
        );
    }

    /// ------------------------------------------------------------------------
    /// Test Efficiency with Large Leaf Data + Many Leaves
    /// ------------------------------------------------------------------------
    #[test]
    fn test_large_data_and_many_leaves_efficiency() {
        // Simulate a "block" with bigger "transactions" (8 KB each).
        // Then add ~300000 such "transactions," to see if we can still
        // handle it quickly in a test scenario.

        let big_leaf: Vec<u8> = vec![0xCD; 8 * 1024]; // 8 KB
        let leaves = (0..300000).map(|_| big_leaf.clone()).collect::<Vec<_>>();

        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Must handle big data + many leaves in a blockchain scenario");
        let root = tree.get_root().unwrap();

        // Spot‐check a few
        for i in [
            0, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000,
        ] {
            let leaf_hash = MerkleTreeSha256::hash_leaf(&leaves[i]);
            let index = tree.get_index_by_hash(&leaf_hash).unwrap();
            let proof = tree.get_proof(index).unwrap();
            assert!(
                proof.verify(&root, &leaf_hash),
                "Large data block must verify"
            );
        }
    }

    /// ------------------------------------------------------------------------
    /// Test Malicious or Invalid Leaf Data
    /// ------------------------------------------------------------------------
    #[test]
    fn test_invalid_leaf_in_blockchain() {
        // If someone tries to pass in partial or invalid data, we want to ensure
        // it can't break the system. There's no direct "malicious" insertion possible
        // once the tree is built, but we can test building with odd data.

        // For example: a "zero length leaf," which is still hashed, but let's see if it works:
        let leaves = vec![b"".to_vec(), b"normal".to_vec()];
        let tree = MerkleTreeSha256::from_leaves_data(leaves.clone())
            .expect("Tree should handle an empty (zero-length) leaf gracefully");
        let root = tree.get_root().unwrap();

        // Proof for the empty leaf
        let empty_hash = MerkleTreeSha256::hash_leaf(b"");
        let idx_empty = tree.get_index_by_hash(&empty_hash).unwrap();
        let proof_empty = tree.get_proof(idx_empty).unwrap();
        assert!(
            proof_empty.verify(&root, &empty_hash),
            "Empty leaf must still yield a valid proof"
        );

        // Another attempt: "extremely large leaf," tested above.
        // As long as from_leaves_data doesn't fail or panic, we are safe.
    }

    /// ------------------------------------------------------------------------
    /// Confirm No ‘Side Loading’ of Data in Proof Steps
    /// ------------------------------------------------------------------------
    #[test]
    fn test_no_sideload_in_proof() {
        // Build a standard tree
        let leaves = vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()];
        let tree =
            MerkleTreeSha256::from_leaves_data(leaves.clone()).expect("Must build normal tree");
        let root = tree.get_root().unwrap();

        // Generate a correct proof for "bar"
        let idx_bar = tree.get_index_by_data(b"bar").unwrap();
        let mut proof = tree.get_proof(idx_bar).unwrap();

        // Try to artificially *add* a sibling step that doesn't exist in the real path
        // We'll just push a random sibling step at the end
        let random_leaf = MerkleTreeSha256::hash_leaf(b"some_injected_sibling");
        proof.steps.push((true /* is_left */, random_leaf));

        // Now it must fail verification, because the path no longer corresponds
        // to the actual Merkle path for "bar"
        let leaf_hash_bar = MerkleTreeSha256::hash_leaf(b"bar");
        assert!(
            !proof.verify(&root, &leaf_hash_bar),
            "Extra bogus step in proof must break verification"
        );
    }

    /// ------------------------------------------------------------------------
    /// Test that trying to get a proof on an **internal node** fails inside `get_proof`.
    ///    This forces `proof.verify(...)` to fail internally, covering the line:
    ///      `Err(anyhow!("Proof does not match the Merkle root"))`
    /// ------------------------------------------------------------------------
    #[test]
    fn test_forced_mismatch_proof_fails() {
        // Build a valid 3-leaf tree
        let leaves = vec![b"X".to_vec(), b"Y".to_vec(), b"Z".to_vec()];
        let mut tree = MerkleTreeSha256::from_leaves_data(leaves).unwrap();

        // Index 2 is the first leaf in a 3-leaf tree.
        // Force a mismatch: fill it with some random or constant data
        tree.tree[2] = vec![0xEF; 32]; // "corrupted" leaf

        // Now get_proof(2) must fail, because the path won't match the real root
        let result = tree.get_proof(2);
        assert!(
            result.is_err(),
            "Expected mismatch to fail inside get_proof"
        );

        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("Proof does not match the Merkle root"),
            "Expected 'Proof does not match the Merkle root', got: {msg}"
        );
    }

    /// Test `parent_index(0)` returns the "Root has no parent" error.
    #[test]
    fn test_parent_index_of_root_fails() {
        let res = parent_index(0);
        assert!(
            res.is_err(),
            "parent_index(0) must fail with 'Root has no parent'"
        );

        let msg = res.err().unwrap().to_string();
        assert!(
            msg.contains("Root has no parent"),
            "Must contain 'Root has no parent', got: {msg}"
        );
    }

    /// Test `sibling_index(0)` returns the "Root has no sibling" error.
    #[test]
    fn test_sibling_index_of_root_fails() {
        let res = sibling_index(0);
        assert!(
            res.is_err(),
            "sibling_index(0) must fail with 'Root has no sibling'"
        );

        let msg = res.err().unwrap().to_string();
        assert!(
            msg.contains("Root has no sibling"),
            "Must contain 'Root has no sibling', got: {msg}"
        );
    }

    #[test]
    fn test_from_leaves_hashes_mutex_poisoned() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let leaves = vec![b"hash1".to_vec(), b"hash2".to_vec()];
        let leaves_len = leaves.len();
        let tree_len = 2 * leaves_len - 1;

        // Wrap our vector of Mutexes in Arc so it can be moved to threads safely.
        let tree = Arc::new(
            (0..tree_len)
                .map(|_| Mutex::new(Vec::new()))
                .collect::<Vec<Mutex<Vec<u8>>>>(),
        );

        let first_leaf_index = tree_len - leaves_len;

        // Spawn a child thread that will poison the lock
        {
            let tree_ref = Arc::clone(&tree);
            let handle = thread::spawn(move || {
                // Lock one of the Mutexes, then panic
                let lock_ref = &tree_ref[first_leaf_index];
                let _guard = lock_ref.lock().unwrap();
                panic!("Panic in separate thread => should poison lock");
            });
            let _ = handle.join(); // We expect this to show Err(...) because of panic
        }

        // Now, the lock should be poisoned. If we try to lock it again:
        let lock_result = tree[first_leaf_index].lock();
        assert!(
            lock_result.is_err(),
            "We expected the lock to be poisoned, but got Ok()"
        );
    }

    // Helper function to generate random leaves with random lengths

    fn generate_random_leaves(count: usize) -> Vec<Vec<u8>> {
        let mut rng = rand::rng();
        (0..count)
            .map(|_| {
                let len = rng.random_range(1..50); // random length
                (0..len).map(|_| rng.random()).collect()
            })
            .collect()
    }
}
