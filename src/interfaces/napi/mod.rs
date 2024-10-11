use crate::domain::{
  hash::hash_sha256,
  proof::{self, MerkleProofInner},
  tree::MerkleTreeInner,
};
use itertools::sorted;
use napi::bindgen_prelude::{Uint32Array, Uint8Array};

type InnerHash = [u8; 32];

#[napi(js_name = "MerkleTreeOptions")]
#[derive(Clone)]
pub struct MerkleTreeOptionsJs {
  pub ordered: bool,
}

impl Default for MerkleTreeOptionsJs {
  fn default() -> Self {
    Self { ordered: true }
  }
}

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
  #[napi]
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
          .map(|i| i.clone() as usize)
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

  #[napi]
  pub fn leaf_index_lookup(&self, data: Uint8Array) -> Option<u64> {
    self
      .inner
      .get_leaf_index(&hash_sha256(&data))
      .map(|i| i.try_into().unwrap())
  }

  #[napi]
  pub fn get_leaf_index(&self, hash: Uint8Array) -> Option<u32> {
    self
      .inner
      .get_leaf_index(&hash.to_vec().try_into().unwrap())
      .map(|i| i.try_into().unwrap())
  }
}

#[napi(js_name = "MerkleProof")]
pub struct MerkleProofJs {
  inner: MerkleProofInner,
}

#[napi]
impl MerkleProofJs {
  #[napi(constructor)]
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

  #[napi]
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

  #[napi]
  pub fn from_bytes_ordered(bytes: Uint8Array) -> napi::Result<Self> {
    Ok(Self {
      inner: MerkleProofInner::from_bytes_ordered(&bytes).unwrap(),
    })
  }

  #[napi]
  pub fn from_bytes_unordered(bytes: Uint8Array) -> napi::Result<Self> {
    Ok(Self {
      inner: MerkleProofInner::from_bytes_unordered(&bytes).unwrap(),
    })
  }

  #[napi]
  pub fn verify_ordered(root: Uint8Array, hash: Uint8Array, leaf_hashes: Vec<Uint8Array>) -> bool {
    MerkleProofInner::verify_ordered(
      root.to_vec().try_into().unwrap(),
      hash.to_vec().try_into().unwrap(),
      &leaf_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<InnerHash>>(),
    )
  }

  #[napi]
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
        .map(|l| l.clone() as usize)
        .collect::<Vec<usize>>(),
      &leaf_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<InnerHash>>(),
      &proof_hashes
        .iter()
        .map(|l| l.to_vec().try_into().unwrap())
        .collect::<Vec<InnerHash>>(),
      total_leaves as usize,
    )
  }

  #[napi]
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
            .map(|l| l.clone() as usize)
            .collect::<Vec<usize>>(),
          leaf_hashes
            .iter()
            .map(|l| l.to_vec().try_into().unwrap())
            .collect::<Vec<InnerHash>>(),
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
