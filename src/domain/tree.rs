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

        // The total size of a complete binary tree in array form
        let tree_len = 2 * leaves_len - 1;

        // Prepare the "empty" tree with default values
        let tree_init_start = Instant::now();
        let tree: Vec<Mutex<Vec<u8>>> = (0..tree_len).map(|_| Mutex::new(Vec::new())).collect();
        debug!("Tree initialization took {:?}", tree_init_start.elapsed());

        // Assign leaves to the bottom of the array
        for (index, hash) in leaves.iter().enumerate() {
            let tree_index = tree_len - 1 - index;
            let mut locked = tree[tree_index]
                .lock()
                .map_err(|_| anyhow!("Mutex poisoned"))?;
            *locked = hash.clone();
        }

        // Recursively build internal nodes
        let build_start = Instant::now();
        let root_hash = build_subtree(&tree, 0, tree_len)?;
        debug!("Building the tree took {:?}", build_start.elapsed());

        // Extract the final Vec<u8>
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

    /// Generate a proof for the leaf at array index `index`. The proof
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

            // If the sibling is less than `node`, it means sibling is on the left side
            let is_left = sibling < node;

            // Save (sibling_hash, sibling_is_left)
            path.push((self.tree[sibling].clone(), is_left));

            node = parent; // move upward
        }

        // The proof steps are from bottom to top in `path`, but we can keep them
        // in that order or reverse them. We just need to apply them in the same sequence
        // we store them. Let’s reverse to get “top-down”: (lowest sibling first).
        path.reverse();

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

/// Build a subtree rooted at `node_index`. Uses Rayon to join left and right children.
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

/// Standard “binary heap” style index calculations:
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
  use crate::domain::tree::{MerkleTreeSha256, MerkleTreeTrait};
  use rand::Rng;

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
        // A small set of deterministic leaves
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

    // Helper function to generate random leaves
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
