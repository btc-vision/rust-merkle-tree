use super::{leaf::MerkleTreeLeafJs, options::MerkleTreeOptionsJs, proof::MerkleProofJs};
use crate::domain::{hash::hash_sha256, tree::MerkleTreeInner};
use itertools::sorted;
use napi::bindgen_prelude::{Uint32Array, Uint8Array};

#[napi(js_name = "MerkleTree")]
pub struct MerkleTreeJs {
  values: Vec<MerkleTreeLeafJs>,
  options: MerkleTreeOptionsJs,
  inner: MerkleTreeInner,
}

#[napi]
impl MerkleTreeJs {
  #[napi]
  pub fn hash(data: Uint8Array) -> Uint8Array {
    hash_sha256(&hash_sha256(&data)).into()
  }

  #[napi(constructor)]
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    Self {
      values: Vec::new(),
      options: MerkleTreeOptionsJs::default(),
      inner: MerkleTreeInner::None,
    }
  }

  #[napi]
  pub fn new_with_options(options: &MerkleTreeOptionsJs) -> Self {
    Self {
      values: Vec::new(),
      options: options.clone(),
      inner: MerkleTreeInner::None,
    }
  }

  #[napi]
  pub fn from_leaves(leaves: Vec<Uint8Array>) -> Self {
    let values: Vec<MerkleTreeLeafJs> = leaves
      .iter()
      .map(|l| MerkleTreeLeafJs::new(l.to_vec()))
      .collect();

    MerkleTreeJs {
      values,
      options: MerkleTreeOptionsJs::default(),
      inner: MerkleTreeInner::None,
    }
  }

  #[napi]
  pub fn set_options(&mut self, options: &MerkleTreeOptionsJs) {
    self.options = options.clone();
  }

  #[napi]
  pub fn hashes(&self) -> Vec<Uint8Array> {
    self.values.iter().map(|v| v.hash.clone().into()).collect()
  }

  #[napi]
  pub fn values(&self) -> Vec<MerkleTreeLeafJs> {
    self.values.clone()
  }

  #[napi]
  pub fn insert(&mut self, leaf: &[u8]) -> Uint8Array {
    let value: MerkleTreeLeafJs = leaf.into();
    let hash = value.hash.clone();
    self.values.push(value);
    hash.into()
  }

  #[napi]
  pub fn append(&mut self, leaves: Vec<Uint8Array>) {
    self.values.append(
      &mut leaves
        .iter()
        .map(|l| MerkleTreeLeafJs::new(l.to_vec()))
        .collect(),
    )
  }
  /**
   * Generate internal tree. Sort the leaves, if it is needed by options
   */
  #[napi(catch_unwind)]
  pub fn generate_tree(&mut self) {
    let leaves = sorted(
      self
        .values
        .iter()
        .map(|l| l.hash.clone().try_into().unwrap()),
    );

    if self.options.ordered {
      self.inner = MerkleTreeInner::from_leaves_ordered(&sorted(leaves).collect::<Vec<[u8; 32]>>());
    } else {
      self.inner = MerkleTreeInner::from_leaves_unordered(&leaves.collect::<Vec<[u8; 32]>>());
    }

    // Todo: not important
    self.inner.commit();
  }

  #[napi]
  pub fn root(&self) -> Option<Uint8Array> {
    self.inner.root().map(|r| r.into())
  }

  #[napi]
  pub fn root_hex(&self) -> Option<String> {
    self.inner.root().map(|r| format!("0x{}", hex::encode(r)))
  }

  /**
   * Create proof from leaves indices
   */
  #[napi]
  pub fn proof(&self, leaf_indices: Uint32Array) -> MerkleProofJs {
    MerkleProofJs::new(
      self.inner.proof(
        &leaf_indices
          .iter()
          .map(|i| *i as usize)
          .collect::<Vec<usize>>(),
      ),
    )
  }

  #[napi]
  pub fn commit(&mut self) {
    self.inner.commit()
  }

  #[napi]
  pub fn rollback(&mut self) {
    self.inner.rollback()
  }

  #[napi(catch_unwind)]
  pub fn leaf_index_lookup(&self, data: Uint8Array) -> Option<u64> {
    self
      .inner
      .get_leaf_index(&hash_sha256(&data))
      .map(|i| i.try_into().unwrap())
  }

  #[napi(catch_unwind)]
  pub fn get_leaf_index(&self, hash: Uint8Array) -> Option<u32> {
    self
      .inner
      .get_leaf_index(&hash.to_vec().try_into().unwrap())
      .map(|i| i.try_into().unwrap())
  }
}
