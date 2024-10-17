use super::tree::MerkleTreeTrait;
use std::marker::PhantomData;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MerkleProofInner<T>
where
  T: MerkleTreeTrait,
{
  hashes: Vec<Vec<u8>>,
  phantom: PhantomData<T>,
}

impl<T> MerkleProofInner<T>
where
  T: MerkleTreeTrait,
{
  pub fn new_from_proof(proof_hashes: Vec<Vec<u8>>) -> Self {
    Self {
      hashes: proof_hashes,
      phantom: PhantomData,
    }
  }

  pub fn proof_hashes(&self) -> Vec<Vec<u8>> {
    self.hashes.clone()
  }

  pub fn root(&self, hash: &[u8]) -> Vec<u8> {
    self
      .hashes
      .iter()
      .fold(hash.to_vec(), |acc, hash| T::hash_nodes(&acc, hash))
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
      MerkleProofInner::<MerkleTreeSha256>::new_from_proof(
        [
          "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
          "7c6ecaee2d838527c849bbb35e136530f348f2fce5de833c1c58ee30c3991ab7",
          "6c593e5a24d589e6af9be6017957b176fc64d3409ede4c22e07d1bebf0b8c90c",
          "698a6ec0545045c135267cd7b40d912d66437e50e0ba74a4b6e9d1f6d17abdf3",
        ]
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect()
      )
      .root(
        &hex::decode("c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e").unwrap()
      ),
      hex::decode("cacbbfa8cec522f5d5e306251bc7115dd88d7ef44f0cf3a84dbddc65481b63fa").unwrap()
    )
  }

  #[test]
  fn test_proof() {
    // 18
    assert!(MerkleProofInner::<MerkleTreeSha256>::new_from_proof(
      [
        "5d351e5962324a1b9920278825ca07b94d020b34941d20d5ac0f44dbbf3a5258",
        "aae47106d882563487de43ea5c0ac5ec53a60e2d3cc9a88f93b0d33cf0c78ddc",
        "4d42ca27311b1512c3d3cd5ac07864264b096981cbc8b19bef642613023ca132",
        "9e54701031c343fbf4d2848a4de7df9252a1bac6b4e4b83e64d14ac44c070e4e",
      ]
      .iter()
      .map(|h| hex::decode(h).unwrap())
      .collect()
    )
    .verify(
      &hex::decode("1eb2fbe0d23ed86d1ad0da939771e8320da2c7de2c341960fe854a7f1ee317c4").unwrap(),
      &hex::decode("493c543220bceffa21283b176955173baa7745d563a7b5e2cae0b4253419a87f").unwrap(),
    ))
  }
}
