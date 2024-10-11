use super::hash::{Sha256Ordered, Sha256UnOrdered};
use rs_merkle::{Error, ErrorKind, Hasher, MerkleProof};

pub enum MerkleProofInner {
  Ordered(MerkleProof<Sha256Ordered>),
  UnOrdered(MerkleProof<Sha256UnOrdered>),
  None,
}

impl MerkleProofInner {
  pub fn new_ordered(proof_hashes: Vec<[u8; 32]>) -> Self {
    MerkleProofInner::Ordered(MerkleProof::new(proof_hashes))
  }

  pub fn new_unordered(proof_hashes: Vec<[u8; 32]>) -> Self {
    MerkleProofInner::UnOrdered(MerkleProof::new(proof_hashes))
  }

  pub fn proof_hashes(&self) -> Vec<[u8; 32]> {
    match self {
      MerkleProofInner::Ordered(proof) => proof.proof_hashes().to_vec(),
      MerkleProofInner::UnOrdered(proof) => proof.proof_hashes().to_vec(),
      _ => Vec::new(),
    }
  }

  pub fn from_bytes_ordered(bytes: &[u8]) -> Result<Self, rs_merkle::Error> {
    Ok(MerkleProofInner::Ordered(MerkleProof::from_bytes(bytes)?))
  }

  pub fn from_bytes_unordered(bytes: &[u8]) -> Result<Self, rs_merkle::Error> {
    Ok(MerkleProofInner::UnOrdered(MerkleProof::from_bytes(bytes)?))
  }

  pub fn root(
    &self,
    leaf_indices: Vec<usize>,
    leaf_hashes: Vec<[u8; 32]>,
    total_leaves_count: usize,
  ) -> Result<[u8; 32], Error> {
    match self {
      MerkleProofInner::Ordered(proof) => {
        proof.root(&leaf_indices, &leaf_hashes, total_leaves_count)
      }
      MerkleProofInner::UnOrdered(proof) => {
        proof.root(&leaf_indices, &leaf_hashes, total_leaves_count)
      }
      _ => Err(Error::new(
        ErrorKind::NotEnoughHelperNodes,
        String::from("Merkle proof is not generated"),
      )),
    }
  }

  pub fn verify_ordered(root: [u8; 32], hash: [u8; 32], proof_hashes: &[[u8; 32]]) -> bool {
    proof_hashes
      .iter()
      .fold(hash, |acc, hash| {
        let result = Sha256Ordered::concat_and_hash(&acc, Some(hash));
        print!(
          "{} {} {}",
          hex::encode(acc),
          hex::encode(hash),
          hex::encode(root)
        );
        result
      })
      .eq(&root)
  }

  pub fn verify_unordered(
    root: [u8; 32],
    leaf_indices: &[usize],
    leaf_hashes: &[[u8; 32]],
    proof_hashes: &[[u8; 32]],
    total_leaves_count: usize,
  ) -> bool {
    let tree: MerkleProof<Sha256Ordered> = MerkleProof::new(proof_hashes.to_vec());
    tree.verify(root, leaf_indices, leaf_hashes, total_leaves_count)
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    match self {
      MerkleProofInner::Ordered(proof) => proof.to_bytes(),
      MerkleProofInner::UnOrdered(proof) => proof.to_bytes(),
      _ => Vec::new(),
    }
  }
}
