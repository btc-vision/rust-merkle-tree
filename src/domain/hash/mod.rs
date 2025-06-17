pub trait HashMethod {
    /// Hash a leaf’s data. (Here: double SHA-256.)
    fn hash_leaf(data: &[u8]) -> Vec<u8>;

    /// Hash two child nodes together. (Here: single SHA-256.)
    fn hash_nodes(left: &[u8], right: &[u8]) -> Vec<u8>;
}

pub mod sha256;
