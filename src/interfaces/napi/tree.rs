use super::proof::MerkleProofJs;
use crate::domain::tree::{MerkleTreeSha256, MerkleTreeTrait};
use napi::bindgen_prelude::Uint8Array;

#[napi(js_name = "MerkleTree")]
pub struct MerkleTreeJs {
  inner: MerkleTreeSha256,
}

#[napi]
impl MerkleTreeJs {
  #[napi]
  pub fn hash(data: Uint8Array) -> Uint8Array {
    MerkleTreeSha256::hash_leaf(&data).into()
  }

  #[napi(constructor)]
  pub fn from_leaves(leaves: Vec<Uint8Array>) -> napi::Result<Self> {
    MerkleTreeSha256::from_leaves_data(leaves.iter().map(|l| l.to_vec()).collect())
      .map(|t| MerkleTreeJs { inner: t })
      .map_err(|err| napi::Error::from_reason(err.to_string()))
  }

  #[napi]
  pub fn hashes(&self) -> Vec<Uint8Array> {
    self.inner.get_hashes().map(|t| t.clone().into()).collect()
  }

  #[napi]
  pub fn root(&self) -> napi::Result<Uint8Array> {
    self
      .inner
      .get_root()
      .map(|r| r.into())
      .map_err(|err| napi::Error::from_reason(err.to_string()))
  }

  #[napi]
  pub fn root_hex(&self) -> napi::Result<String> {
    self
      .inner
      .get_root()
      .map(|r| format!("0x{}", hex::encode(r)))
      .map_err(|err| napi::Error::from_reason(err.to_string()))
  }

  /**
   * Create proof from leaves indices
   */
  #[napi]
  pub fn get_proof(&self, leaf_index: u32) -> napi::Result<MerkleProofJs> {
    self
      .inner
      .get_proof(leaf_index as usize)
      .map(MerkleProofJs::new_inner)
      .map_err(|err| napi::Error::from_reason(err.to_string()))
  }

  #[napi(catch_unwind)]
  pub fn get_index_data(&self, data: Uint8Array) -> napi::Result<u32> {
    self
      .inner
      .get_index_by_data(&data)
      .map(|r| r as u32)
      .map_err(|e| napi::Error::from_reason(e.to_string()))
  }

  #[napi(catch_unwind)]
  pub fn get_index_hash(&self, hash: Uint8Array) -> napi::Result<u32> {
    self
      .inner
      .get_index_by_hash(&hash)
      .map(|r| r as u32)
      .map_err(|e| napi::Error::from_reason(e.to_string()))
  }
}
