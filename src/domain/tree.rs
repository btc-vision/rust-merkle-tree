use super::{
  hash::{Sha256Ordered, Sha256UnOrdered},
  proof::MerkleProofInner,
};
use rs_merkle::MerkleTree;

pub enum MerkleTreeInner {
  Ordered(MerkleTree<Sha256Ordered>),
  UnOrdered(MerkleTree<Sha256UnOrdered>),
  None,
}

impl MerkleTreeInner {
  pub fn from_leaves_ordered(leaves: &[[u8; 32]]) -> Self {
    Self::Ordered(MerkleTree::from_leaves(leaves))
  }

  pub fn from_leaves_unordered(leaves: &[[u8; 32]]) -> Self {
    Self::UnOrdered(MerkleTree::from_leaves(leaves))
  }

  pub fn commit(&mut self) {
    match self {
      Self::Ordered(tree) => tree.commit(),
      Self::UnOrdered(tree) => tree.commit(),
      _ => (),
    }
  }

  pub fn rollback(&mut self) {
    match self {
      Self::Ordered(tree) => tree.rollback(),
      Self::UnOrdered(tree) => tree.rollback(),
      _ => (),
    }
  }

  pub fn root(&self) -> Option<[u8; 32]> {
    match self {
      Self::Ordered(tree) => tree.root(),
      Self::UnOrdered(tree) => tree.root(),
      _ => None,
    }
  }

  pub fn proof(&self, leaf_indices: &[usize]) -> MerkleProofInner {
    match self {
      Self::Ordered(tree) => MerkleProofInner::Ordered(tree.proof(leaf_indices)),
      Self::UnOrdered(tree) => MerkleProofInner::UnOrdered(tree.proof(leaf_indices)),
      _ => MerkleProofInner::None,
    }
  }

  pub fn get_leaf_index(&self, hash: &[u8; 32]) -> Option<usize> {
    match self {
      Self::Ordered(tree) => tree
        .leaves()
        .iter()
        .flatten()
        .enumerate()
        .find(|(_, &l)| l.eq(hash))
        .map(|(i, _)| i),
      Self::UnOrdered(tree) => tree
        .leaves()
        .iter()
        .flatten()
        .enumerate()
        .find(|(_, &l)| l.eq(hash))
        .map(|(i, _)| i),
      _ => None,
    }
  }
}
