use crate::domain::tree::{MerkleTreeSha256, MerkleTreeTrait};

use crate::interfaces::MerkleProofJs;
use napi::{bindgen_prelude::Uint8Array, Error, Status};

#[napi(js_name = "MerkleTree")]
pub struct MerkleTreeJs {
    inner: MerkleTreeSha256,
}

#[napi]
impl MerkleTreeJs {
    /// Hash a piece of data using the library's leaf-hash function (double SHA-256).
    #[napi]
    pub fn hash(data: Uint8Array) -> Uint8Array {
        MerkleTreeSha256::hash_leaf(&data).into()
    }

    /// Build a Merkle tree from raw leaves data.
    #[napi(constructor)]
    pub fn from_leaves(leaves: Vec<Uint8Array>) -> napi::Result<Self> {
        let data_vec = leaves.into_iter().map(|l| l.to_vec()).collect();
        match MerkleTreeSha256::from_leaves_data(data_vec) {
            Ok(tree) => Ok(MerkleTreeJs { inner: tree }),
            Err(e) => Err(Error::new(Status::InvalidArg, e.to_string())),
        }
    }

    /// Returns the underlying tree's leaf-level (hashed) data.
    #[napi]
    pub fn hashes(&self) -> Vec<Uint8Array> {
        self.inner.get_hashes().map(|t| t.clone().into()).collect()
    }

    /// Return the Merkle root as bytes.
    #[napi]
    pub fn root(&self) -> napi::Result<Uint8Array> {
        match self.inner.get_root() {
            Ok(r) => Ok(r.into()),
            Err(e) => Err(Error::new(Status::GenericFailure, e.to_string())),
        }
    }

    /// Return the Merkle root in hex format, 0x-prefixed.
    #[napi]
    pub fn root_hex(&self) -> napi::Result<String> {
        match self.inner.get_root() {
            Ok(r) => Ok(format!("0x{}", hex::encode(r))),
            Err(e) => Err(Error::new(Status::GenericFailure, e.to_string())),
        }
    }

    /// Create a proof for a specific leaf index.
    #[napi]
    pub fn get_proof(&self, leaf_index: u32) -> napi::Result<MerkleProofJs> {
        match self.inner.get_proof(leaf_index as usize) {
            Ok(proof) => Ok(MerkleProofJs::new_inner(proof)),
            Err(e) => Err(Error::new(Status::InvalidArg, e.to_string())),
        }
    }

    /// Return the index of `data` (double-hashed) in the tree, or error if not found.
    #[napi]
    pub fn get_index_data(&self, data: Uint8Array) -> napi::Result<u32> {
        match self.inner.get_index_by_data(&data) {
            Ok(idx) => Ok(idx as u32),
            Err(e) => Err(Error::new(Status::InvalidArg, e.to_string())),
        }
    }

    /// Return the index of a hashed leaf in the tree, or error if not found.
    #[napi]
    pub fn get_index_hash(&self, hash: Uint8Array) -> napi::Result<u32> {
        match self.inner.get_index_by_hash(&hash) {
            Ok(idx) => Ok(idx as u32),
            Err(e) => Err(Error::new(Status::InvalidArg, e.to_string())),
        }
    }
}
