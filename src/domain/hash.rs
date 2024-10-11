use rs_merkle::Hasher;
use sha2::{digest::FixedOutput, Digest, Sha256};

pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(data);
  hasher.finalize_fixed().into()
}

#[derive(Clone)]
pub struct Sha256Ordered {}
impl Hasher for Sha256Ordered {
  type Hash = [u8; 32];

  fn hash(data: &[u8]) -> Self::Hash {
    hash_sha256(data)
  }
  fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
    match right {
      Some(right_node) => Self::hash(&if left.cmp(right_node) == std::cmp::Ordering::Less {
        left
          .iter()
          .chain(right_node.iter())
          .cloned()
          .collect::<Vec<u8>>()
      } else {
        right_node
          .iter()
          .chain(left.iter())
          .cloned()
          .collect::<Vec<u8>>()
      }),
      None => *left,
    }
  }
}

#[derive(Clone)]
pub struct Sha256UnOrdered {}

impl Hasher for Sha256UnOrdered {
  type Hash = [u8; 32];

  fn hash(data: &[u8]) -> Self::Hash {
    hash_sha256(data)
  }

  fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
    match right {
      Some(right_node) => Self::hash(
        &left
          .iter()
          .chain(right_node.iter())
          .cloned()
          .collect::<Vec<u8>>(),
      ),
      None => *left,
    }
  }
}
