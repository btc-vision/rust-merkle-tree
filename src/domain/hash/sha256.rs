use super::HashMethod;
use sha2::{digest::FixedOutput, Digest, Sha256};

pub struct Sha256Normal;
impl HashMethod for Sha256Normal {
    fn hash_leaf(data: &[u8]) -> Vec<u8> {
        // Double SHA-256 for leaf data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let once = hasher.finalize_fixed();

        let mut hasher = Sha256::new();
        hasher.update(once);
        hasher.finalize_fixed().to_vec()
    }

    fn hash_nodes(left: &[u8], right: &[u8]) -> Vec<u8> {
        // Single SHA-256 for internal nodes
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize_fixed().to_vec()
    }
}

pub struct Sha256Canonical;
impl HashMethod for Sha256Canonical {
    fn hash_leaf(data: &[u8]) -> Vec<u8> {
        // Double SHA-256 for leaf data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let once = hasher.finalize_fixed();

        let mut hasher = Sha256::new();
        hasher.update(once);
        hasher.finalize_fixed().to_vec()
    }

    fn hash_nodes(left: &[u8], right: &[u8]) -> Vec<u8> {
        // Single SHA-256 for internal nodes
        let mut hasher = Sha256::new();
        if left.gt(right) {
            hasher.update(left);
            hasher.update(right);
        } else {
            hasher.update(right);
            hasher.update(left);
        }
        hasher.finalize_fixed().to_vec()
    }
}
