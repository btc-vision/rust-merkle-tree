use napi::bindgen_prelude::Uint8Array;

use crate::domain::{
  proof::MerkleProofInner,
  tree::{MerkleTreeSha256, MerkleTreeTrait},
};

/// JavaScript-facing MerkleProof wrapper.
#[napi(js_name = "MerkleProof")]
pub struct MerkleProofJs {
  inner: MerkleProofInner<MerkleTreeSha256>,
}

#[napi]
impl MerkleProofJs {
  /// Create from an array of `[Uint8Array, bool]` pairs if you like,
  /// but for simplicity we'll do a single constructor here that
  /// expects you to supply the pairs in a structured way, or
  /// you might rely on MerkleTreeJs::get_proof below to create it.
  #[napi(constructor)]
  pub fn new(steps: Vec<JsProofStep>) -> napi::Result<Self> {
    let mut converted = Vec::with_capacity(steps.len());
    for js_step in steps {
      converted.push((js_step.sibling.to_vec(), js_step.is_left));
    }
    Ok(Self {
      inner: MerkleProofInner::new(converted),
    })
  }

  /// We use this so the Tree can build a `MerkleProofInner` in Rust and wrap it.
  pub fn new_inner(inner: MerkleProofInner<MerkleTreeSha256>) -> Self {
    MerkleProofJs { inner }
  }

  /// Return true or false for a given root and leaf-hash.
  #[napi]
  pub fn verify(&self, root: Uint8Array, leaf: Uint8Array) -> bool {
    self.inner.verify(&root, &leaf)
  }

  /// Like verify, but we first do double-hash of `data` to get the leaf-hash.
  #[napi]
  pub fn verify_data(&self, root: Uint8Array, data: Uint8Array) -> bool {
    let leaf_hash = MerkleTreeSha256::hash_leaf(&data);
    self.inner.verify(&root, &leaf_hash)
  }

  /// Return the computed Merkle root when starting from `leaf_hash`.
  #[napi]
  pub fn root(&self, leaf_hash: Uint8Array) -> Uint8Array {
    self.inner.root(&leaf_hash).into()
  }

  #[napi]
  pub fn root_hex(&self, leaf_hash: Uint8Array) -> String {
    let out = self.inner.root(&leaf_hash);
    format!("0x{}", hex::encode(out))
  }

  /// Return all sibling hashes in the proof (direction flags omitted).
  #[napi]
  pub fn proof_hashes(&self) -> Vec<Uint8Array> {
    self
      .inner
      .proof_hashes()
      .into_iter()
      .map(Into::into)
      .collect()
  }

  #[napi]
  pub fn proof_hashes_hex(&self) -> Vec<String> {
    self
      .inner
      .proof_hashes()
      .into_iter()
      .map(|h| format!("0x{}", hex::encode(h)))
      .collect()
  }
}

#[napi(object)]
pub struct JsProofStep {
  /// The sibling’s hash (Uint8Array) in raw bytes
  pub sibling: Uint8Array,
  /// Whether the sibling is on the left side
  pub is_left: bool,
}
