use log::{debug, info};
use rayon::prelude::*;
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::sync::Mutex;
use std::time::Instant;

pub trait MerkleTreeTrait {
  fn hash_leaf(data: &[u8]) -> Vec<u8>;
  fn hash_nodes(first: &[u8], second: &[u8]) -> Vec<u8>;
  fn left_child_index(i: usize) -> usize {
    2 * i + 1
  }
  fn right_child_index(i: usize) -> usize {
    2 * i + 2
  }
  fn parent_index(i: usize) -> anyhow::Result<usize> {
    if i > 0 {
      Ok((i - 1) / 2)
    } else {
      Err(anyhow::anyhow!("Root has no parent"))
    }
  }
  fn sibling_index(i: usize) -> anyhow::Result<usize> {
    let i = i as i32;
    if i > 0 {
      Ok((i - ((-1_i32).pow((i % 2) as u32))) as usize)
    } else {
      Err(anyhow::anyhow!("Root has no siblings"))
    }
  }
  fn tree_index(len: usize, pos: usize) -> anyhow::Result<usize> {
    if pos >= len {
      Err(anyhow::anyhow!("Pos is more then len"))
    } else {
      Ok(len * 2 - 2 - pos)
    }
  }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MerkleTreeSha256 {
  tree: Vec<Vec<u8>>,
  root: Option<Vec<u8>>,
}

impl MerkleTreeTrait for MerkleTreeSha256 {
  fn hash_leaf(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);

    let data2 = hasher.finalize_fixed();
    let mut hasher = Sha256::new();
    hasher.update(data2);

    hasher.finalize_fixed().to_vec()
  }

  fn hash_nodes(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);

    hasher.finalize_fixed().to_vec()
  }
}

impl MerkleTreeSha256 {
  pub fn from_leaves_data(leaves: Vec<Vec<u8>>) -> anyhow::Result<Self> {
    let hashed_leaves: Vec<_> = leaves
      .par_iter()
      .map(|leaf| Self::hash_leaf(leaf))
      .collect();

    Self::from_leaves_hashes(hashed_leaves)
  }

  pub fn from_leaves_hashes(leaves: Vec<Vec<u8>>) -> anyhow::Result<Self> {
    // Initialize the logger at the start of your application, not here
    // env_logger::init();

    let total_start = Instant::now();

    let leaves_len = leaves.len();
    if leaves_len == 0 {
      return Err(anyhow::anyhow!("Leaves cannot be empty"));
    }

    let tree_len = 2 * leaves_len - 1;

    // Wrap each element of the tree in a Mutex for interior mutability
    let tree_init_start = Instant::now();
    let tree: Vec<Mutex<Vec<u8>>> = (0..tree_len).map(|_| Mutex::new(Vec::new())).collect();
    debug!("Tree initialization took {:?}", tree_init_start.elapsed());

    let setup_start = Instant::now();
    debug!(
      "Setup (leaves_iterator creation) took {:?}",
      setup_start.elapsed()
    );

    // Assign leaves to the tree
    let assign_start = Instant::now();
    for (index, hash) in leaves.iter().enumerate() {
      let tree_index = tree_len - 1 - index;
      *tree[tree_index].lock().unwrap() = hash.clone();
    }
    debug!(
      "Assigning leaves to the tree took {:?}",
      assign_start.elapsed()
    );

    // Build the tree recursively in parallel
    let build_start = Instant::now();
    let root_hash = Self::build_subtree(&tree, 0, tree_len);
    debug!("Building the tree took {:?}", build_start.elapsed());

    // Extract the tree vector from the Mutexes
    let extract_start = Instant::now();
    let tree_vec: Vec<Vec<u8>> = tree
      .into_iter()
      .map(|mutex| mutex.into_inner().unwrap())
      .collect();
    debug!("Extracting tree vector took {:?}", extract_start.elapsed());

    // Build tree_map and hash_map
    let map_build_start = Instant::now();

    debug!(
      "Building tree_map and hash_map took {:?}",
      map_build_start.elapsed()
    );

    let total_duration = total_start.elapsed();
    info!("Total duration of from_leaves_hashes: {:?}", total_duration);

    Ok(Self {
      root: Some(root_hash),
      tree: tree_vec,
    })
  }

  fn build_subtree(tree: &[Mutex<Vec<u8>>], node_index: usize, tree_len: usize) -> Vec<u8> {
    if MerkleTreeSha256::left_child_index(node_index) >= tree_len {
      // Leaf node, already assigned
      tree[node_index].lock().unwrap().clone()
    } else {
      let left_child = MerkleTreeSha256::left_child_index(node_index);
      let right_child = MerkleTreeSha256::right_child_index(node_index);

      let (left_hash, right_hash) = rayon::join(
        || Self::build_subtree(tree, left_child, tree_len),
        || Self::build_subtree(tree, right_child, tree_len),
      );

      let parent_hash = MerkleTreeSha256::hash_nodes(&left_hash, &right_hash);
      *tree[node_index].lock().unwrap() = parent_hash.clone();
      parent_hash
    }
  }

  pub fn get_hashes(&self) -> impl Iterator<Item = &Vec<u8>> {
    self.tree.iter().skip(self.tree.len() / 2)
  }

  pub fn get_index_by_data(&self, data: &[u8]) -> anyhow::Result<usize> {
    self.get_index_by_hash(&Self::hash_leaf(data))
  }

  pub fn get_index_by_hash(&self, hash: &[u8]) -> anyhow::Result<usize> {
    self
      .tree
      .iter()
      .position(|h| h.eq(hash))
      .ok_or(anyhow::anyhow!("hash did not found"))
  }

  pub fn get_root(&self) -> anyhow::Result<Vec<u8>> {
    Ok(self.root.clone().expect("Root is not generated"))
  }

  pub fn get_proof(&self, index: usize) -> anyhow::Result<super::proof::MerkleProofInner<Self>> {
    let mut tree_index = index;
    let mut proof_hashes = Vec::new();
    while tree_index > 0 {
      proof_hashes.push(self.tree[Self::sibling_index(tree_index)?].clone());
      tree_index = Self::parent_index(tree_index)?;
    }
    let proof = super::proof::MerkleProofInner::new_from_index(proof_hashes, index);

    let leaf_hash = self.tree.get(index).expect("Hash does not exist in tree");

    if proof.verify(
      self.root.as_ref().expect("root does not generated"),
      leaf_hash,
    ) {
      Ok(proof)
    } else {
      Err(anyhow::anyhow!("Checksum does not match the root"))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::super::proof::MerkleProofInner;
  use super::MerkleTreeSha256;
  use super::MerkleTreeTrait;

  fn steps() -> Vec<usize> {
    vec![
      1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
      89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
      191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
      283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
      401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
      509, 521, 523, 541,
    ]
  }

  fn check_tree(hashes: [&str; 12], root: &str) -> MerkleTreeSha256 {
    let tree = MerkleTreeSha256::from_leaves_hashes(
      hashes.iter().map(|h| hex::decode(h).unwrap()).collect(),
    )
    .unwrap();

    // Test proof for each element of the tree
    for hash in hashes.iter() {
      let hash_bytes = hex::decode(hash).unwrap();
      let proof = tree
        .get_proof(tree.get_index_by_hash(&hash_bytes).unwrap())
        .unwrap();
      assert!(proof.verify(&hex::decode(root).unwrap(), &hash_bytes));
    }

    assert_eq!(tree.get_root().unwrap(), hex::decode(root).unwrap());
    tree
  }

  // WARNING: DO NOT USE IN PRODUCTION, NON DETERMINISTIC
  fn check_proof(number: usize) {
    let hashes = (0..number)
      .map(|_| (0..32).map(|_| rand::random::<u8>()).collect::<Vec<u8>>())
      .collect::<Vec<Vec<u8>>>();

    let tree = MerkleTreeSha256::from_leaves_hashes(hashes.clone()).unwrap();

    let root = tree.root.as_ref().unwrap();
    for hash in hashes.iter() {
      let i = tree.get_index_by_hash(hash).unwrap();
      let proof = tree.get_proof(i.clone()).unwrap();
      assert!(proof.verify(root, &hash));
    }
  }

  #[test]
  fn test_tree_unsorted() {
    let tree = check_tree(
      [
        "2e3580210116e2ab7c7705f8f0b6217ac7a0ac5f31de892f847171c073a7542f",
        "016a2b39a42811f88585a5e07ee3a57283607b47816945d61354577ff8868378",
        "93ca042c86dafda63e1a03b4625f614dc9364231e986d72490a480a4cc591c4a",
        "af4f1bfe5c512e9265718f3fa9a028f7e70b29860c705763ecbb541f4a5877ce",
        "5d351e5962324a1b9920278825ca07b94d020b34941d20d5ac0f44dbbf3a5258",
        "713af6f789258961f0ed63b4073060bae6ba7e8b92bcb5383ebe18e6e76289d6",
        "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
        "c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e",
        "33b544b8002201957eaa0816c4ee2bc244d4cce765e599df6f25adbb2cdb0c08",
        "493c543220bceffa21283b176955173baa7745d563a7b5e2cae0b4253419a87f",
        "96ca5d6526e42a2a9da666e27cd8332c3a6b4cada4561726401f66ba08eaaa42",
        "a0e25bb110b98aa9c3e2be61e432cb432788d0dbe29991acd8ced7c7d9386aea",
      ],
      "3182eef79a093bac51458d77b984c513a473573ef129b41268e062fc2b2d4caa",
    );
    let index = tree
      .get_index_by_hash(
        &hex::decode("a0e25bb110b98aa9c3e2be61e432cb432788d0dbe29991acd8ced7c7d9386aea").unwrap(),
      )
      .unwrap();

    assert_eq!(index, MerkleTreeSha256::tree_index(12, 11).unwrap());
    let proof = tree.get_proof(index).unwrap();
    assert_eq!(
      proof,
      MerkleProofInner::<MerkleTreeSha256>::new_from_pos_len(
        [
          "96ca5d6526e42a2a9da666e27cd8332c3a6b4cada4561726401f66ba08eaaa42",
          "f623586be521ccdb9862dea9e6c9541b113f3497c89e3f72315a8e12d1dbb754",
          "294f589e294c5187b6f62f23953b88431450bfc9ce0ad53d712772d78b1b049a",
        ]
        .iter()
        .map(|h| hex::decode(h).unwrap())
        .collect(),
        11,
        12,
      )
    );
  }

  #[test]
  fn test_unsorted() {
    for n in steps() {
      check_proof(n);
    }
  }

  // Audit
  #[test]
  fn test_2() {
    // Original set of hashes
    let hashes_1 = [
      "93ca042c86dafda63e1a03b4625f614dc9364231e986d72490a480a4cc591c4a",
      "713af6f789258961f0ed63b4073060bae6ba7e8b92bcb5383ebe18e6e76289d6",
      "5d351e5962324a1b9920278825ca07b94d020b34941d20d5ac0f44dbbf3a5258",
      "493c543220bceffa21283b176955173baa7745d563a7b5e2cae0b4253419a87f",
      "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
      "33b544b8002201957eaa0816c4ee2bc244d4cce765e599df6f25adbb2cdb0c08",
      "2e3580210116e2ab7c7705f8f0b6217ac7a0ac5f31de892f847171c073a7542f",
      "016a2b39a42811f88585a5e07ee3a57283607b47816945d61354577ff8868378",
      "c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e",
      "af4f1bfe5c512e9265718f3fa9a028f7e70b29860c705763ecbb541f4a5877ce",
      "a0e25bb110b98aa9c3e2be61e432cb432788d0dbe29991acd8ced7c7d9386aea",
      "96ca5d6526e42a2a9da666e27cd8332c3a6b4cada4561726401f66ba08eaaa42",
    ];

    // Construct a Merkle tree with unsorted input
    let tree_1 = MerkleTreeSha256::from_leaves_hashes(
      hashes_1.iter().map(|h| hex::decode(h).unwrap()).collect(),
    )
    .unwrap();

    // Rearrange nodes by swapping the first two hashes
    let hashes_2 = [
      "713af6f789258961f0ed63b4073060bae6ba7e8b92bcb5383ebe18e6e76289d6",
      "93ca042c86dafda63e1a03b4625f614dc9364231e986d72490a480a4cc591c4a",
      "5d351e5962324a1b9920278825ca07b94d020b34941d20d5ac0f44dbbf3a5258",
      "493c543220bceffa21283b176955173baa7745d563a7b5e2cae0b4253419a87f",
      "39e429c0920f4089a43dbe24a7dfcfe0552bdaabfcc9356cde88f9ea18972bf4",
      "33b544b8002201957eaa0816c4ee2bc244d4cce765e599df6f25adbb2cdb0c08",
      "2e3580210116e2ab7c7705f8f0b6217ac7a0ac5f31de892f847171c073a7542f",
      "016a2b39a42811f88585a5e07ee3a57283607b47816945d61354577ff8868378",
      "c67892017db365f15687b283fea0741145e1b54a62430fd814e1755c6e25949e",
      "af4f1bfe5c512e9265718f3fa9a028f7e70b29860c705763ecbb541f4a5877ce",
      "a0e25bb110b98aa9c3e2be61e432cb432788d0dbe29991acd8ced7c7d9386aea",
      "96ca5d6526e42a2a9da666e27cd8332c3a6b4cada4561726401f66ba08eaaa42",
    ];

    // Construct another tree with rearranged input
    let tree_2 = MerkleTreeSha256::from_leaves_hashes(
      hashes_2.iter().map(|h| hex::decode(h).unwrap()).collect(),
    )
    .unwrap();

    // Both trees produce the same root hash despite different structures
    assert_ne!(tree_1.get_root().unwrap(), tree_2.get_root().unwrap());
  }
}
