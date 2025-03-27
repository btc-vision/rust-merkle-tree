pub mod canonical;
pub mod normal;

pub trait MerkleProofTrait {
    fn root(&self, leaf_hash: &[u8]) -> Vec<u8>;

    fn proof_hashes(&self) -> Vec<Vec<u8>>;

    /// Verify a proof by comparing the recomputed root with `root`.
    fn verify(&self, root: &[u8], leaf_hash: &[u8]) -> bool {
        self.root(leaf_hash) == root
    }
}
