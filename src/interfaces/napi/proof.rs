use crate::domain::{
  proof::MerkleProofInner,
  tree::{MerkleTreeSha256, MerkleTreeTrait},
};

use napi::{bindgen_prelude::Uint8Array, JsNumber};

#[napi(js_name = "MerkleProof")]
pub struct MerkleProofJs {
  inner: MerkleProofInner<MerkleTreeSha256>,
}

#[napi]
impl MerkleProofJs {
  #[napi(constructor, catch_unwind)]
  pub fn new_from_pos_len(proof_hashes: Vec<Uint8Array>, pos: JsNumber, len: JsNumber) -> Self {
    MerkleProofJs {
      inner: MerkleProofInner::new_from_pos_len(
        proof_hashes.iter().map(|p| p.to_vec()).collect(),
        TryInto::<u32>::try_into(pos).unwrap() as usize,
        TryInto::<u32>::try_into(len).unwrap() as usize,
      ),
    }
  }

  #[napi]
  pub fn new_proof(proof_hashes: Vec<Uint8Array>, tree_index: JsNumber) -> Self {
    MerkleProofJs {
      inner: MerkleProofInner::new_from_index(
        proof_hashes.iter().map(|p| p.to_vec()).collect(),
        TryInto::<u32>::try_into(tree_index).unwrap() as usize,
      ),
    }
  }

  pub fn new_inner(inner: MerkleProofInner<MerkleTreeSha256>) -> Self {
    Self { inner }
  }

  #[napi]
  pub fn verify(&self, root: Uint8Array, hash: Uint8Array) -> bool {
    self.inner.verify(&root, &hash)
  }

  #[napi]
  pub fn verify_data(&self, root: Uint8Array, data: Uint8Array) -> bool {
    let hash = MerkleTreeSha256::hash_leaf(&data);
    self.inner.verify(&root, &hash)
  }

  #[napi]
  pub fn root(&self, hash: Uint8Array) -> Uint8Array {
    self.inner.root(&hash).into()
  }

  #[napi]
  pub fn root_hex(&self, hash: Uint8Array) -> String {
    format!("0x{}", hex::encode(self.inner.root(&hash)))
  }

  #[napi]
  pub fn proof_hashes(&self) -> Vec<Uint8Array> {
    self
      .inner
      .proof_hashes()
      .iter()
      .map(|h| h.clone().into())
      .collect()
  }

  #[napi]
  pub fn proof_hashes_hex(&self) -> Vec<String> {
    self
      .inner
      .proof_hashes()
      .iter()
      .map(|h| format!("0x{}", hex::encode(h)))
      .collect()
  }
}
