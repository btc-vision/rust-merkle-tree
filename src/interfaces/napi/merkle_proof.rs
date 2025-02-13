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
    /// Constructor that expects each step to have a single `Uint8Array` of length 33:
    ///   * byte 0 => 0x01 if is_left=true, or 0x00 if is_left=false
    ///   * bytes 1..=32 => the sibling's hash
    #[napi(constructor)]
    pub fn new(steps: Vec<Uint8Array>) -> napi::Result<Self> {
        let mut converted = Vec::with_capacity(steps.len());
        for js_step in steps {
            let data = js_step.to_vec();

            if data.is_empty() {
                return Err(napi::Error::from_reason("Uint8Array.data cannot be empty"));
            }

            if data.len() != 33 {
                return Err(napi::Error::from_reason(
                    "Uint8Array.data must be 33 bytes long",
                ));
            }

            // The first byte encodes is_left
            let is_left_byte = data[0];
            let is_left = is_left_byte != 0;

            // The sibling-hash is the remaining 32 bytes
            let sibling_hash = data[1..].to_vec();

            converted.push((is_left, sibling_hash));
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

    /// Return each proof step as a 33-byte array:
    ///   * byte 0 => 0x01 if is_left=true, else 0x00
    ///   * bytes 1..=32 => the sibling hash
    #[napi]
    pub fn proof_hashes(&self) -> Vec<Uint8Array> {
        self.inner
            .steps
            .iter()
            .map(|(is_left, hash)| {
                let mut combined = Vec::with_capacity(33);
                // First byte is direction
                combined.push(if *is_left { 1 } else { 0 });
                // Next 32 bytes are sibling hash
                combined.extend_from_slice(hash);
                combined.into()
            })
            .collect()
    }

    #[napi]
    pub fn proof_hashes_hex(&self) -> Vec<String> {
        self.inner
            .steps
            .iter()
            .map(|(is_left, hash)| {
                let mut combined = Vec::with_capacity(33);
                combined.push(if *is_left { 1 } else { 0 });
                combined.extend_from_slice(hash);
                format!("0x{}", hex::encode(combined))
            })
            .collect()
    }
}
