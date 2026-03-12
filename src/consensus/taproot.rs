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
