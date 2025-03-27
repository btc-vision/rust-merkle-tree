use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Status};

use crate::domain::hash::sha256::Sha256Canonical;
use crate::domain::hash::{sha256::Sha256Normal, HashMethod};
use crate::domain::tree::canonical::MerkleTreeCanonicalSha256;
use crate::domain::tree::{
    canonical::MerkleTreeCanonical, normal::MerkleTreeNormalSha256, MerkleTreeTrait,
};
use crate::interfaces::{MerkleProofCanonicalSha256Js, MerkleProofNormalSha256Js};

#[napi(js_name = "MerkleTree")]
pub struct MerkleTreeNormalSha256Js {
    inner: MerkleTreeNormalSha256,
}

#[napi]
impl MerkleTreeNormalSha256Js {
    /// Hash a piece of data using the library's leaf-hash function (double SHA-256).
    #[napi]
    pub fn hash(data: Uint8Array) -> Uint8Array {
        Sha256Normal::hash_leaf(&data).into()
    }

    /// Build a Merkle tree from raw leaves data.
    #[napi(constructor)]
    pub fn from_leaves(leaves: Vec<Uint8Array>) -> napi::Result<Self> {
        let data_vec = leaves.into_iter().map(|l| l.to_vec()).collect();
        match MerkleTreeNormalSha256::from_leaves_data(data_vec) {
            Ok(tree) => Ok(MerkleTreeNormalSha256Js { inner: tree }),
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
    pub fn root(&self) -> Uint8Array {
        self.inner.get_root().into()
    }

    /// Return the Merkle root in hex format, 0x-prefixed.
    #[napi]
    pub fn root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.get_root()))
    }

    /// Create a proof for a specific leaf index.
    #[napi]
    pub fn get_proof(&self, leaf_index: u32) -> napi::Result<MerkleProofNormalSha256Js> {
        match self.inner.get_proof(leaf_index as usize) {
            Ok(proof) => Ok(MerkleProofNormalSha256Js::new_inner(proof)),
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

#[napi(js_name = "MerkleTreeCanonical")]
pub struct MerkleTreeCanonicalSha256Js {
    inner: MerkleTreeCanonicalSha256,
}

#[napi]
impl MerkleTreeCanonicalSha256Js {
    /// Hash a piece of data using the library's leaf-hash function (double SHA-256).
    #[napi]
    pub fn hash(data: Uint8Array) -> Uint8Array {
        Sha256Canonical::hash_leaf(&data).into()
    }

    /// Build a Merkle tree from raw leaves data.
    #[napi(constructor)]
    pub fn from_leaves(leaves: Vec<Uint8Array>) -> napi::Result<Self> {
        let data_vec = leaves.into_iter().map(|l| l.to_vec()).collect();
        match MerkleTreeCanonicalSha256::from_leaves_data(data_vec) {
            Ok(tree) => Ok(MerkleTreeCanonicalSha256Js { inner: tree }),
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
    pub fn root(&self) -> Uint8Array {
        self.inner.get_root().into()
    }

    /// Return the Merkle root in hex format, 0x-prefixed.
    #[napi]
    pub fn root_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.get_root()))
    }

    /// Create a proof for a specific leaf index.
    #[napi]
    pub fn get_proof(&self, leaf_index: u32) -> napi::Result<MerkleProofCanonicalSha256Js> {
        match self.inner.get_proof(leaf_index as usize) {
            Ok(proof) => Ok(MerkleProofCanonicalSha256Js::new_inner(proof)),
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
