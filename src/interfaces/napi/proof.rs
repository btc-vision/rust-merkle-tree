use crate::domain::proof::MerkleProofInner;
use napi::bindgen_prelude::{Uint32Array, Uint8Array};

#[napi(js_name = "MerkleProof")]
pub struct MerkleProofJs {
  inner: MerkleProofInner,
}

#[napi]
impl MerkleProofJs {
  #[napi(constructor, catch_unwind)]
  pub fn new_ordered(proof_hashes: Vec<Uint8Array>) -> Self {
    MerkleProofJs {
      inner: MerkleProofInner::new_ordered(
        proof_hashes
          .iter()
          .map(|p| p.to_vec().try_into().unwrap())
          .collect(),
      ),
    }
  }

  #[napi(catch_unwind)]
  pub fn new_unordered(proof_hashes: Vec<Uint8Array>) -> Self {
    MerkleProofJs {
      inner: MerkleProofInner::new_unordered(
        proof_hashes
          .iter()
          .map(|p| p.to_vec().try_into().unwrap())
          .collect(),
      ),
    }
  }

  pub fn new(inner: MerkleProofInner) -> Self {
    MerkleProofJs { inner }
  }

  #[napi(catch_unwind)]
  pub fn from_bytes_ordered(bytes: Uint8Array) -> napi::Result<Self> {
    Ok(Self {
      inner: MerkleProofInner::from_bytes_ordered(&bytes).unwrap(),
    })
  }

  #[napi(catch_unwind)]
  pub fn from_bytes_unordered(bytes: Uint8Array) -> napi::Result<Self> {
    Ok(Self {
      inner: MerkleProofInner::from_bytes_unordered(&bytes).unwrap(),
    })
  }

  #[napi(catch_unwind)]
  pub fn verify_ordered(root: Uint8Array, hash: Uint8Array, leaf_hashes: Vec<Uint8Array>) -> bool {
    MerkleProofInner::verify_ordered(
      root.to_vec().try_into().unwrap(),
      hash.to_vec().try_into().unwrap(),
      &leaf_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<super::InnerHash>>(),
    )
  }

  #[napi(catch_unwind)]
  pub fn verify_unordered(
    root: Uint8Array,
    leaf_indices: Uint32Array,
    leaf_hashes: Vec<Uint8Array>,
    proof_hashes: Vec<Uint8Array>,
    total_leaves: u32,
  ) -> bool {
    MerkleProofInner::verify_unordered(
      root.to_vec().try_into().unwrap(),
      &leaf_indices
        .iter()
        .map(|l| *l as usize)
        .collect::<Vec<usize>>(),
      &leaf_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<super::InnerHash>>(),
      &proof_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<super::InnerHash>>(),
      total_leaves as usize,
    )
  }

  #[napi(catch_unwind)]
  pub fn root(
    &self,
    leaf_indices: Uint32Array,
    leaf_hashes: Vec<Uint8Array>,
    total_leaves_count: u32,
  ) -> napi::Result<Uint8Array> {
    Ok(
      self
        .inner
        .root(
          leaf_indices
            .iter()
            .map(|l| *l as usize)
            .collect::<Vec<usize>>(),
          leaf_hashes
            .iter()
            .map(|l| l.to_vec().try_into().unwrap())
            .collect::<Vec<super::InnerHash>>(),
          total_leaves_count.try_into().unwrap(),
        )
        .unwrap()
        .into(),
    )
  }

  #[napi]
  pub fn root_hex(
    &self,
    leaf_indices: Uint32Array,
    leaf_hashes: Vec<Uint8Array>,
    total_leaves_count: u32,
  ) -> napi::Result<String> {
    self
      .root(leaf_indices, leaf_hashes, total_leaves_count)
      .map(|r| format!("0x{}", hex::encode(r)))
  }

  #[napi]
  pub fn proof_hashes(&self) -> Vec<Uint8Array> {
    self.inner.proof_hashes().iter().map(|h| h.into()).collect()
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

  #[napi]
  pub fn to_bytes(&self) -> Uint8Array {
    self.inner.to_bytes().into()
  }
}
