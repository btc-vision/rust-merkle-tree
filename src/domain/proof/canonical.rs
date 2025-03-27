use std::marker::PhantomData;

use crate::domain::hash::{sha256::Sha256Canonical, HashMethod};

use super::MerkleProofTrait;

pub struct MerkleProofCanonical<Method>
where
    Method: HashMethod,
{
    pub steps: Vec<Vec<u8>>,
    pub method: PhantomData<Method>,
}

impl<Method: HashMethod> MerkleProofTrait for MerkleProofCanonical<Method> {
    /// Return the sibling hashes only, with direction flags as the last byte.
    fn proof_hashes(&self) -> Vec<Vec<u8>> {
        self.steps.clone()
    }

    /// Compute the Merkle root by folding over `(sibling, is_left)`.
    fn root(&self, leaf_hash: &[u8]) -> Vec<u8> {
        let mut current = leaf_hash.to_vec();

        for hash in self.steps.iter() {
            current = Method::hash_nodes(hash, &current);
        }
        current
    }
}

impl<Method: HashMethod> MerkleProofCanonical<Method> {
    pub fn new(steps: Vec<Vec<u8>>) -> Self {
        Self {
            steps,
            method: PhantomData,
        }
    }
}

pub type MerkleProofCanonicalSha256 = MerkleProofCanonical<Sha256Canonical>;

#[cfg(test)]
mod tests {
    use crate::domain::hash::{sha256::Sha256Canonical, HashMethod};
    use crate::domain::proof::{
        canonical::{MerkleProofCanonical, MerkleProofCanonicalSha256},
        MerkleProofTrait,
    };

    #[test]
    fn test_no_steps_proof() {
        // If the proof has no siblings, the leaf must be the root itself
        let proof = MerkleProofCanonical::<Sha256Canonical>::new(vec![]);
        let leaf = b"single_leaf";
        let leaf_hash = Sha256Canonical::hash_leaf(leaf);

        // If 'leaf_hash' is also the root, verification is true
        assert!(
            proof.verify(&leaf_hash, &leaf_hash),
            "No-step proof must succeed only when leaf == root"
        );

        let random_root = Sha256Canonical::hash_leaf(b"some_other_data");
        assert!(
            !proof.verify(&random_root, &leaf_hash),
            "Should fail if root != leaf for a no-step proof"
        );
    }

    #[test]
    fn test_single_step_left() {
        // If sibling is on the left, we do hash_nodes(sibling, current)
        let leaf_data = b"leaf_data";
        let leaf_hash = Sha256Canonical::hash_leaf(leaf_data);

        let sibling_data = b"sibling_data";
        let sibling_hash = Sha256Canonical::hash_leaf(sibling_data);

        // is_left = true => order is (sibling, leaf)
        let proof_steps = vec![sibling_hash.clone()];
        let proof = MerkleProofCanonical::<Sha256Canonical>::new(proof_steps);

        let correct_root = Sha256Canonical::hash_nodes(&sibling_hash, &leaf_hash);
        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Proof must succeed if the sibling is on the left"
        );

        let incorrect_root = Sha256Canonical::hash_nodes(&leaf_hash, &sibling_hash);
        assert!(
            proof.verify(&incorrect_root, &leaf_hash),
            "Swapping the order should pass"
        );
    }

    #[test]
    fn test_single_step_right() {
        // If sibling is on the right, we do hash_nodes(current, sibling)
        let leaf_data = b"left_leaf";
        let leaf_hash = Sha256Canonical::hash_leaf(leaf_data);

        let sibling_data = b"right_leaf";
        let sibling_hash = Sha256Canonical::hash_leaf(sibling_data);

        // is_left = false => order is (leaf, sibling)
        let proof_steps = vec![sibling_hash.clone()];
        let proof = MerkleProofCanonical::<Sha256Canonical>::new(proof_steps);

        let correct_root = Sha256Canonical::hash_nodes(&leaf_hash, &sibling_hash);
        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Right-step proof must succeed with correct order"
        );

        let incorrect_root = Sha256Canonical::hash_nodes(&sibling_hash, &leaf_hash);
        assert!(
            proof.verify(&incorrect_root, &leaf_hash),
            "Inverted order must pass"
        );
    }

    #[test]
    fn test_multi_step_proof() {
        // We'll construct a small Merkle structure by hand:
        //         R
        //       /   \
        //     N1     N2
        //    /  \   /  \
        //   A    B C    D
        // Leaf-level => double-hash: A, B, C, D
        // Internal nodes => single-hash: N1 = H(A,B), N2 = H(C,D)
        // Root => R = H(N1, N2)
        let a = Sha256Canonical::hash_leaf(b"A");
        let b = Sha256Canonical::hash_leaf(b"B");
        let c = Sha256Canonical::hash_leaf(b"C");
        let d = Sha256Canonical::hash_leaf(b"D");

        let n1 = Sha256Canonical::hash_nodes(&a, &b);
        let n2 = Sha256Canonical::hash_nodes(&c, &d);
        let r = Sha256Canonical::hash_nodes(&n1, &n2);

        // We want the proof for leaf = B => path is:
        // 1) sibling = A, is_left=true => hash_nodes(A,B) => N1
        // 2) sibling = N2, is_left=false => hash_nodes(N1,N2) => R
        let proof_steps = vec![
            a.clone(),  // A is left
            n2.clone(), // N2 is right
        ];
        let proof = MerkleProofCanonical::<Sha256Canonical>::new(proof_steps);

        // Verify
        assert!(
            proof.verify(&r, &b),
            "Manually built multi-step proof must match the final root"
        );

        // Confirm it fails if we supply the wrong root
        let fake_root = Sha256Canonical::hash_leaf(b"fake_root");
        assert!(!proof.verify(&fake_root, &b), "Wrong root must fail");
    }

    #[test]
    fn test_proof_hashes_and_hex() {
        // Just ensure `proof_hashes()` and a hypothetical hex function
        // produce the correct data. We'll do a one-step proof for simplicity.
        //let leaf_data = b"leaf_data";
        //let leaf_hash = MerkleTreeSha256::hash_leaf(leaf_data);

        let sibling_data = b"sibling_data";
        let sibling_hash = Sha256Canonical::hash_leaf(sibling_data);

        let proof = MerkleProofCanonical::<Sha256Canonical>::new(vec![sibling_hash.clone()]);
        let all_hashes = proof.proof_hashes();
        assert_eq!(
            all_hashes.len(),
            1,
            "One-step proof must have exactly 1 sibling"
        );

        //sibling_hash.push(1); // Right sibling
        assert_eq!(
            all_hashes[0], sibling_hash,
            "Proof hash must match the sibling's hash"
        );
    }
}
