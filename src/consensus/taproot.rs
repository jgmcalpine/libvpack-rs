//! BIP-341 Taproot tree hashing primitives: TapLeaf, TapBranch, and tagged hash.
//! Pure `no_std` implementation using the library's SHA-256 and CompactSize logic.

use alloc::vec::Vec;

use crate::compact_size::write_compact_size;
use crate::types::hashes::sha256::Hash as Sha256Hash;
use crate::types::hashes::Hash;

pub(crate) const TAPLEAF_VERSION: u8 = 0xc0;

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
    tap_leaf_hash_with_version(TAPLEAF_VERSION, script)
}

/// TapLeaf hash with an explicit `leaf_version` (control byte with parity cleared; typically `0xc0`).
pub fn tap_leaf_hash_with_version(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 5 + script.len());
    payload.push(leaf_version);
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

/// Sibling hashes from `leaf_index` to the Merkle root for `compute_balanced_merkle_root` topology
/// (consecutive pairwise reduction; odd tail promoted without a partner).
pub fn balanced_merkle_sibling_path(
    leaf_hashes: &[[u8; 32]],
    leaf_index: usize,
) -> Option<Vec<[u8; 32]>> {
    if leaf_hashes.is_empty() || leaf_index >= leaf_hashes.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaf_hashes.to_vec();
    let mut pos = leaf_index;
    while level.len() > 1 {
        let len = level.len();
        if pos % 2 == 1 {
            path.push(level[pos - 1]);
        } else if pos + 1 < len {
            path.push(level[pos + 1]);
        }
        // else: `pos` is the unpaired tail (odd `len`) — no sibling at this level.

        let mut next = Vec::with_capacity(len.div_ceil(2));
        let mut i = 0;
        while i + 1 < len {
            next.push(tap_branch_hash(level[i], level[i + 1]));
            i += 2;
        }
        if i < len {
            next.push(level[i]);
        }

        pos = if pos.is_multiple_of(2) && pos + 1 >= len {
            next.len().checked_sub(1)?
        } else {
            pos / 2
        };
        level = next;
    }
    Some(path)
}

/// BIP-341 TapTweak: compute the tweaked x-only public key from an internal key
/// and Merkle root. Returns the 32-byte x-coordinate of Q = P + t*G, where
/// t = TaggedHash("TapTweak", internal_key || merkle_root).
///
/// When the `bitcoin` feature is enabled, this uses **rust-secp256k1** (same stack as the rest of
/// Taproot in `rust-bitcoin`). With `schnorr-verify` but without `bitcoin` (e.g. wasm preset), this
/// falls back to **k256** so path-exclusivity checks can still run.
///
/// Returns `None` if the internal key is not a valid secp256k1 x-coordinate or
/// the tweak hash is not a valid scalar.
#[cfg(feature = "bitcoin")]
pub fn compute_taproot_tweak(internal_key: [u8; 32], merkle_root: [u8; 32]) -> Option<[u8; 32]> {
    let (x, _) = compute_taproot_tweaked_key_x_and_parity(internal_key, merkle_root)?;
    Some(x)
}

#[cfg(all(feature = "schnorr-verify", not(feature = "bitcoin")))]
pub fn compute_taproot_tweak(internal_key: [u8; 32], merkle_root: [u8; 32]) -> Option<[u8; 32]> {
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
    let encoded = EncodedPoint::from_bytes(compressed).ok()?;
    let p: AffinePoint = Option::from(AffinePoint::from_encoded_point(&encoded))?;

    let tweak_scalar: Scalar = Scalar::from_repr_vartime(tweak_hash.into())?;

    let q: ProjectivePoint = ProjectivePoint::from(p) + ProjectivePoint::GENERATOR * tweak_scalar;
    let q_affine = q.to_affine();
    let q_encoded = q_affine.to_encoded_point(false);

    let x = q_encoded.x()?;
    let mut result = [0u8; 32];
    result.copy_from_slice(x.as_ref());
    Some(result)
}

/// BIP-341 tweaked output key: x-only coordinate and the parity bit for the taproot control block.
///
/// Implemented with **rust-secp256k1** via the `bitcoin` crate (no k256).
#[cfg(feature = "bitcoin")]
pub fn compute_taproot_tweaked_key_x_and_parity(
    internal_key: [u8; 32],
    merkle_root: [u8; 32],
) -> Option<([u8; 32], u8)> {
    use bitcoin::hashes::Hash;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::taproot::TapNodeHash;
    use bitcoin::XOnlyPublicKey;

    let secp = Secp256k1::verification_only();
    let internal = XOnlyPublicKey::from_slice(&internal_key).ok()?;
    let root = TapNodeHash::from_byte_array(merkle_root);
    let (tweaked, parity) = internal.tap_tweak(&secp, Some(root));
    let x = tweaked.to_x_only_public_key().serialize();
    Some((x, parity.to_u8()))
}
