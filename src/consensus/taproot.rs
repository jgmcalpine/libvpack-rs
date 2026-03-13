//! BIP-341 Taproot tree hashing primitives: TapLeaf, TapBranch, and tagged hash.
//! Pure `no_std` implementation using the library's SHA-256 and CompactSize logic.

use alloc::vec::Vec;

use crate::compact_size::write_compact_size;
use crate::types::hashes::sha256::Hash as Sha256Hash;
use crate::types::hashes::Hash;

const TAPLEAF_VERSION: u8 = 0xc0;

/// BIP-341 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || payload)`.
pub fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256Hash::hash(tag);
    let mut inner = Vec::with_capacity(64 + payload.len());
    inner.extend_from_slice(&tag_hash.to_byte_array());
    inner.extend_from_slice(&tag_hash.to_byte_array());
    inner.extend_from_slice(payload);
    Sha256Hash::hash(&inner).to_byte_array()
}

/// BIP-341 TapLeaf hash: `tagged_hash("TapLeaf", leaf_version || compact_size(script.len()) || script)`.
pub fn tap_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 5 + script.len());
    payload.push(TAPLEAF_VERSION);
    write_compact_size(&mut payload, script.len() as u64);
    payload.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &payload)
}

/// BIP-341 TapBranch hash: lexicographically sort `a` and `b`, then
/// `tagged_hash("TapBranch", smaller || larger)`.
pub fn tap_branch_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&left);
    payload[32..].copy_from_slice(&right);
    tagged_hash(b"TapBranch", &payload)
}

/// Balanced Merkle root from a slice of leaf hashes using pairwise bottom-up
/// construction. Adjacent pairs are combined with `tap_branch_hash` (which
/// handles lexicographic sorting per BIP-341). If a level has an odd number of
/// nodes the last element is promoted to the next level.
/// Returns `None` for an empty slice.
pub fn compute_balanced_merkle_root(leaf_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaf_hashes.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaf_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(tap_branch_hash(level[i], level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    Some(level[0])
}

/// BIP-341 TapTweak: compute the tweaked x-only public key from an internal key
/// and Merkle root. Returns the 32-byte x-coordinate of Q = P + t*G, where
/// t = TaggedHash("TapTweak", internal_key || merkle_root).
#[cfg(feature = "schnorr-verify")]
pub fn compute_taproot_tweak(internal_key: [u8; 32], merkle_root: [u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::ff::PrimeField;
    use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&internal_key);
    payload[32..].copy_from_slice(&merkle_root);
    let tweak_hash = tagged_hash(b"TapTweak", &payload);

    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&internal_key);
    let encoded =
        EncodedPoint::from_bytes(compressed).expect("33-byte compressed point is valid encoding");
    let p: AffinePoint = AffinePoint::from_encoded_point(&encoded).unwrap();

    let tweak_scalar: Scalar =
        Scalar::from_repr_vartime(tweak_hash.into()).expect("tweak hash is a valid scalar");

    let q: ProjectivePoint = ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * tweak_scalar;
    let q_affine = q.to_affine();
    let q_encoded = q_affine.to_encoded_point(false);

    let x = q_encoded.x().expect("tweaked point is not identity");
    let mut result = [0u8; 32];
    result.copy_from_slice(x.as_ref());
    result
}
