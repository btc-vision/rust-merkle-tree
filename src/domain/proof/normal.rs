use std::marker::PhantomData;

use crate::domain::hash::{sha256::Sha256Normal, HashMethod};

use super::MerkleProofTrait;

/// A Merkle proof that holds a list of `(sibling_hash, is_left)` pairs.
/// `is_left = true` means the sibling is on the left side, so the order is `(sib, current)`.
/// `is_left = false` means sibling is on the right, so the order is `(current, sib)`.
///

pub struct MerkleProofNormal<Method>
where
    Method: HashMethod,
{
    pub steps: Vec<(bool, Vec<u8>)>,
    pub method: PhantomData<Method>,
}

impl<Method: HashMethod> MerkleProofTrait for MerkleProofNormal<Method> {
    /// Return the sibling hashes only, with direction flags as the last byte.
    fn proof_hashes(&self) -> Vec<Vec<u8>> {
        self.steps
            .iter()
            .map(|(_is_left, sib)| {
                let hash = sib.clone();
                hash
            })
            .collect()
    }

    /// Compute the Merkle root by folding over `(sibling, is_left)`.
    fn root(&self, leaf_hash: &[u8]) -> Vec<u8> {
        let mut current = leaf_hash.to_vec();

        for (is_left, sib) in self.steps.iter() {
            if *is_left {
                current = Method::hash_nodes(sib, &current);
            } else {
                current = Method::hash_nodes(&current, sib);
            }
        }
        current
    }
}

impl<Method: HashMethod> MerkleProofNormal<Method> {
    pub fn new(steps: Vec<(bool, Vec<u8>)>) -> Self {
        Self {
            steps,
            method: PhantomData,
        }
    }
}

pub type MerkleProofNormalSha256 = MerkleProofNormal<Sha256Normal>;

#[cfg(test)]
mod tests {
    use crate::domain::hash::{sha256::Sha256Normal, HashMethod};
    use crate::domain::proof::{normal::MerkleProofNormal, MerkleProofTrait};

    #[test]
    fn test_no_steps_proof() {
        // If the proof has no siblings, the leaf must be the root itself
        let proof = MerkleProofNormal::<Sha256Normal>::new(vec![]);
        let leaf = b"single_leaf";
        let leaf_hash = Sha256Normal::hash_leaf(leaf);

        // If 'leaf_hash' is also the root, verification is true
        assert!(
            proof.verify(&leaf_hash, &leaf_hash),
            "No-step proof must succeed only when leaf == root"
        );

        let random_root = Sha256Normal::hash_leaf(b"some_other_data");
        assert!(
            !proof.verify(&random_root, &leaf_hash),
            "Should fail if root != leaf for a no-step proof"
        );
    }

    #[test]
    fn test_single_step_left() {
        // If sibling is on the left, we do hash_nodes(sibling, current)
        let leaf_data = b"leaf_data";
        let leaf_hash = Sha256Normal::hash_leaf(leaf_data);

        let sibling_data = b"sibling_data";
        let sibling_hash = Sha256Normal::hash_leaf(sibling_data);

        // is_left = true => order is (sibling, leaf)
        let proof_steps = vec![(true, sibling_hash.clone())];
        let proof = MerkleProofNormal::<Sha256Normal>::new(proof_steps);

        let correct_root = Sha256Normal::hash_nodes(&sibling_hash, &leaf_hash);
        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Proof must succeed if the sibling is on the left"
        );

        let incorrect_root = Sha256Normal::hash_nodes(&leaf_hash, &sibling_hash);
        assert!(
            !proof.verify(&incorrect_root, &leaf_hash),
            "Swapping the order should fail"
        );
    }

    #[test]
    fn test_single_step_right() {
        // If sibling is on the right, we do hash_nodes(current, sibling)
        let leaf_data = b"left_leaf";
        let leaf_hash = Sha256Normal::hash_leaf(leaf_data);

        let sibling_data = b"right_leaf";
        let sibling_hash = Sha256Normal::hash_leaf(sibling_data);

        // is_left = false => order is (leaf, sibling)
        let proof_steps = vec![(false, sibling_hash.clone())];
        let proof = MerkleProofNormal::<Sha256Normal>::new(proof_steps);

        let correct_root = Sha256Normal::hash_nodes(&leaf_hash, &sibling_hash);
        assert!(
            proof.verify(&correct_root, &leaf_hash),
            "Right-step proof must succeed with correct order"
        );

        let incorrect_root = Sha256Normal::hash_nodes(&sibling_hash, &leaf_hash);
        assert!(
            !proof.verify(&incorrect_root, &leaf_hash),
            "Inverted order must fail"
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
        let a = Sha256Normal::hash_leaf(b"A");
        let b = Sha256Normal::hash_leaf(b"B");
        let c = Sha256Normal::hash_leaf(b"C");
        let d = Sha256Normal::hash_leaf(b"D");

        let n1 = Sha256Normal::hash_nodes(&a, &b);
        let n2 = Sha256Normal::hash_nodes(&c, &d);
        let r = Sha256Normal::hash_nodes(&n1, &n2);

        // We want the proof for leaf = B => path is:
        // 1) sibling = A, is_left=true => hash_nodes(A,B) => N1
        // 2) sibling = N2, is_left=false => hash_nodes(N1,N2) => R
        let proof_steps = vec![
            (true, a.clone()),   // A is left
            (false, n2.clone()), // N2 is right
        ];
        let proof = MerkleProofNormal::<Sha256Normal>::new(proof_steps);

        // Verify
        assert!(
            proof.verify(&r, &b),
            "Manually built multi-step proof must match the final root"
        );

        // Confirm it fails if we supply the wrong root
        let fake_root = Sha256Normal::hash_leaf(b"fake_root");
        assert!(!proof.verify(&fake_root, &b), "Wrong root must fail");
    }

    #[test]
    fn test_proof_hashes_and_hex() {
        // Just ensure `proof_hashes()` and a hypothetical hex function
        // produce the correct data. We'll do a one-step proof for simplicity.
        //let leaf_data = b"leaf_data";
        //let leaf_hash = MerkleTreeSha256::hash_leaf(leaf_data);

        let sibling_data = b"sibling_data";
        let sibling_hash = Sha256Normal::hash_leaf(sibling_data);

        let proof = MerkleProofNormal::<Sha256Normal>::new(vec![(true, sibling_hash.clone())]);
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

    #[test]
    fn test_malicious_proof_fails() {
        // If we flip the direction bits or the sibling data, verification must fail
        let leaf_data = b"victim_leaf";
        let leaf_hash = Sha256Normal::hash_leaf(leaf_data);

        let sibling = b"sibling_data";
        let sibling_hash = Sha256Normal::hash_leaf(sibling);

        // Suppose the real direction is 'false' => (leaf, sibling)
        // We'll build a proof with direction = 'true' => (sibling, leaf)
        let malicious_proof =
            MerkleProofNormal::<Sha256Normal>::new(vec![(true, sibling_hash.clone())]);

        // The "correct" root if sibling is on the right
        let correct_root = Sha256Normal::hash_nodes(&leaf_hash, &sibling_hash);

        assert!(
            !malicious_proof.verify(&correct_root, &leaf_hash),
            "Malicious proof flipping direction must fail"
        );
    }
}
