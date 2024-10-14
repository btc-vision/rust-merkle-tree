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
