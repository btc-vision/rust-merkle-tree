#[napi(js_name = "MerkleTreeOptions")]
#[derive(Clone)]
pub struct MerkleTreeOptionsJs {
  pub sort_leaves: bool,
}

impl Default for MerkleTreeOptionsJs {
  fn default() -> Self {
    Self { sort_leaves: true }
  }
}
