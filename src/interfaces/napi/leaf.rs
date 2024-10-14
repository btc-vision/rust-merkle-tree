use crate::domain::hash::hash_sha256;

#[napi(js_name = "MerkleTreeLeaf")]
#[derive(Clone)]
pub struct MerkleTreeLeafJs {
  pub data: Vec<u8>,
  pub hash: Vec<u8>,
}

impl MerkleTreeLeafJs {
  pub fn new(data: Vec<u8>) -> Self {
    Self {
      hash: hash_sha256(&hash_sha256(&data)).to_vec(),
      data,
    }
  }
}

impl From<&[u8]> for MerkleTreeLeafJs {
  fn from(value: &[u8]) -> Self {
    Self::new(value.to_vec())
  }
}
