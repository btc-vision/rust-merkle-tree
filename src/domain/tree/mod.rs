use anyhow::{anyhow, Result};
use log::{debug, info};
use rayon::prelude::*;
use std::sync::Mutex;
use std::time::Instant;

use super::hash::HashMethod;

pub mod canonical;
pub mod normal;

pub trait MerkleTreeTrait<Method: HashMethod>: Sized {
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

    fn build_subtree(
        tree: &[Mutex<Vec<u8>>],
        node_index: usize,
        tree_len: usize,
    ) -> Result<Vec<u8>> {
        let left = Self::left_child_index(node_index);
        // If left >= tree_len, we’re a leaf
        if left >= tree_len {
            let locked = tree[node_index]
                .lock()
                .map_err(|_| anyhow!("Mutex poisoned"))?;
            return Ok(locked.clone());
        }

        let right = Self::right_child_index(node_index);

        let (left_hash_res, right_hash_res) = rayon::join(
            || Self::build_subtree(tree, left, tree_len),
            || Self::build_subtree(tree, right, tree_len),
        );

        let left_hash = left_hash_res?;
        let right_hash = right_hash_res?;

        let parent_hash = Method::hash_nodes(&left_hash, &right_hash);
        let mut locked = tree[node_index]
            .lock()
            .map_err(|_| anyhow!("Mutex poisoned"))?;
        *locked = parent_hash.clone();
        Ok(parent_hash)
    }

    fn new(tree: Vec<Vec<u8>>, root: Vec<u8>) -> Self;

    fn get_hashes(&self) -> impl Iterator<Item = &Vec<u8>>;

    /// Return the Merkle root, or error if missing (should never be if built properly).
    fn get_root(&self) -> Vec<u8>;

    /// Return the index of data (after double-hash) in the tree, or error if not found.
    fn get_index_by_data(&self, data: &[u8]) -> Result<usize>;

    /// Return the index of a hashed leaf in the array, or error if not found.
    fn get_index_by_hash(&self, hash: &[u8]) -> Result<usize>;

    fn from_leaves_data(leaves: Vec<Vec<u8>>) -> Result<Self> {
        let hashed_leaves: Vec<_> = leaves
            .par_iter()
            .map(|leaf| Method::hash_leaf(leaf))
            .collect();
        Self::from_leaves_hashes(hashed_leaves)
    }

    fn from_leaves_hashes(leaves: Vec<Vec<u8>>) -> Result<Self>;

    /// Build a MerkleTreeSha256 from already-hashed leaves.
    fn from_leaves_hashes_base(leaves: Vec<Vec<u8>>) -> Result<Self> {
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
        let root_hash = Self::build_subtree(&tree, 0, tree_len)?;
        debug!("Building the tree took {:?}", total_start.elapsed());

        let extract_start = Instant::now();
        let final_tree: Vec<Vec<u8>> = tree
            .into_iter()
            .map(|m| m.into_inner().unwrap_or_default())
            .collect();
        debug!("Extracting tree vector took {:?}", extract_start.elapsed());

        let total_duration = total_start.elapsed();
        info!("Total duration of from_leaves_hashes: {:?}", total_duration);

        Ok(Self::new(final_tree, root_hash))
    }
}
