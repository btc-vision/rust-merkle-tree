use super::tree::MerkleTreeTrait;
use std::marker::PhantomData;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MerkleProofInner<T>
where
  T: MerkleTreeTrait,
{
  hashes: Vec<Vec<u8>>,
  tree_index: usize,
  phantom: PhantomData<T>,
}

impl<T> MerkleProofInner<T>
where
  T: MerkleTreeTrait,
{
  pub fn new_from_pos_len(proof_hashes: Vec<Vec<u8>>, pos: usize, len: usize) -> Self {
    Self::new_from_index(proof_hashes, T::tree_index(len, pos).unwrap())
  }

  pub fn new_from_index(proof_hashes: Vec<Vec<u8>>, tree_index: usize) -> Self {
    Self {
      hashes: proof_hashes,
      tree_index,
      phantom: PhantomData,
    }
  }

  pub fn proof_hashes(&self) -> Vec<Vec<u8>> {
    self.hashes.clone()
  }

  pub fn root(&self, hash: &[u8]) -> Vec<u8> {
    let mut pos = self.tree_index;
    let mut index = 0;
    let mut hash = hash.to_vec();

    while pos > 0 && index < self.hashes.len() {
      let sibling = T::sibling_index(pos).unwrap();
      if sibling > pos {
        hash = T::hash_nodes(&hash, &self.hashes[index]);
      } else {
        hash = T::hash_nodes(&self.hashes[index], &hash);
      }
      index += 1;
      pos = T::parent_index(pos).unwrap();
    }

    hash
  }

  pub fn verify(&self, root: &[u8], hash: &[u8]) -> bool {
    self.root(hash).eq(root)
  }
}

#[cfg(test)]
mod tests {
  use super::super::tree::MerkleTreeSha256;
  use super::MerkleProofInner;

  #[test]
  fn test_root() {
    assert_eq!(
      MerkleProofInner::<MerkleTreeSha256>::new_from_pos_len(
        [
          "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
          "7c6ecaee2d838527c849bbb35e136530f348f2fce5de833c1c58ee30c3991ab7",
          "6c593e5a24d589e6af9be6017957b176fc64d3409ede4c22e07d1bebf0b8c90c",
          "698a6ec0545045c135267cd7b40d912d66437e50e0ba74a4b6e9d1f6d17abdf3",
        ]
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect(),
        0,
        12,
      )
      .root(
        &hex::decode("c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e").unwrap()
      ),
      hex::decode("70cfcac08c42aa7a6a162365d7fdc7e4b0f2b39f1c90fb9e4794ec587371e892").unwrap()
    )
  }

  #[test]
  fn test_proof() {
    // 18
    assert!(MerkleProofInner::<MerkleTreeSha256>::new_from_pos_len(
      [
        "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
        "7c6ecaee2d838527c849bbb35e136530f348f2fce5de833c1c58ee30c3991ab7",
        "6c593e5a24d589e6af9be6017957b176fc64d3409ede4c22e07d1bebf0b8c90c",
        "698a6ec0545045c135267cd7b40d912d66437e50e0ba74a4b6e9d1f6d17abdf3",
      ]
      .iter()
      .map(|h| hex::decode(h).unwrap())
      .collect(),
      0,
      12
    )
    .verify(
      &hex::decode("70cfcac08c42aa7a6a162365d7fdc7e4b0f2b39f1c90fb9e4794ec587371e892").unwrap(),
      &hex::decode("c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e").unwrap(),
    ))
  }
}
