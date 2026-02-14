//! BIP-341 Taproot Sighash (SigMsg + TapSighash tagged hash).
//! no_std; single-input SIGHASH_DEFAULT only. Used for GenesisItem Schnorr verification.

#![cfg(feature = "schnorr-verify")]

use alloc::vec::Vec;

use byteorder::{ByteOrder, LittleEndian};
use k256::schnorr::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};

use crate::compact_size::write_compact_size;
use crate::consensus::{TxInPreimage, TxOutPreimage};
use crate::error::VPackError;
use crate::types::hashes::sha256::Hash as Sha256Hash;
use crate::types::hashes::Hash;

const TAP_SIGHASH_TAG: &[u8] = b"TapSighash";

/// P2TR script prefix: OP_1 (0x51) push 32 bytes (0x20).
const P2TR_SCRIPT_PREFIX: &[u8] = &[0x51, 0x20];

/// Extracts the 32-byte x-only public key for BIP-340 verification.
///
/// - If `script` is P2TR form (51 20 <32-byte-key>), returns the last 32 bytes.
/// - If `script` is already 32 bytes (raw x-only), returns it as-is.
/// - Otherwise returns `None`.
pub fn extract_verify_key(script: &[u8]) -> Option<[u8; 32]> {
    if script.len() == 34 && script.starts_with(P2TR_SCRIPT_PREFIX) {
        script[2..34].try_into().ok()
    } else if script.len() == 32 {
        script.try_into().ok()
    } else {
        None
    }
}

/// Test-only: signs a sighash with a fixed test key and returns (signature, pubkey).
#[cfg(any(test, feature = "schnorr-verify"))]
pub fn sign_sighash_for_test(sighash: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    use k256::schnorr::signature::hazmat::PrehashSigner;
    use k256::schnorr::SigningKey;
    let key_bytes = [0x42u8; 32];
    let signing_key =
        SigningKey::from_bytes((&key_bytes[..]).into()).expect("fixed test key is valid");
    let sig = signing_key.sign_prehash(sighash).expect("sign");
    let pk = signing_key.verifying_key().to_bytes();
    (sig.to_bytes(), pk.into())
}

/// Verifies a 64-byte BIP-340 Schnorr signature over `msg` with the given x-only pubkey.
pub fn verify_schnorr_bip340(
    pubkey_x: &[u8; 32],
    msg: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), VPackError> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey_x).map_err(|_| VPackError::InvalidSignature)?;
    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| VPackError::InvalidSignature)?;
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| VPackError::InvalidSignature)
}

/// BIP-341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || x).
fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256Hash::hash(tag);
    let mut inner = Vec::with_capacity(64 + payload.len());
    inner.extend_from_slice(&tag_hash.to_byte_array());
    inner.extend_from_slice(&tag_hash.to_byte_array());
    inner.extend_from_slice(payload);
    let h = Sha256Hash::hash(&inner);
    h.to_byte_array()
}

/// Serialize a single outpoint for sha_prevouts (32 bytes txid + 4 bytes vout LE).
fn serialize_prevout(prev_out_txid: &[u8; 32], prev_out_vout: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(prev_out_txid);
    let mut vout_buf = [0u8; 4];
    LittleEndian::write_u32(&mut vout_buf, prev_out_vout);
    out.extend_from_slice(&vout_buf);
    out
}

/// Serialize scriptPubKey as in CTxOut (compact size + script bytes).
fn serialize_script_for_ctxout(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + script.len());
    write_compact_size(&mut out, script.len() as u64);
    out.extend_from_slice(script);
    out
}

/// Serialize a single output in CTxOut format (8 value LE + compact size + script).
fn serialize_output(value: u64, script_pubkey: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 1 + script_pubkey.len());
    let mut val_buf = [0u8; 8];
    LittleEndian::write_u64(&mut val_buf, value);
    out.extend_from_slice(&val_buf);
    write_compact_size(&mut out, script_pubkey.len() as u64);
    out.extend_from_slice(script_pubkey);
    out
}

/// Compute BIP-341 Taproot sighash for a single-input virtual transaction (SIGHASH_DEFAULT).
///
/// Commits to the spending tx (version, locktime, single input outpoint/sequence),
/// the **parent** (spent) output's amount and scriptPubKey, and the spending tx's outputs.
/// Used to verify the 64-byte Schnorr signature on a GenesisItem.
pub fn taproot_sighash(
    version: u32,
    locktime: u32,
    input: &TxInPreimage,
    parent_amount: u64,
    parent_script_pubkey: &[u8],
    outputs: &[TxOutPreimage<'_>],
) -> [u8; 32] {
    let mut sig_msg = Vec::with_capacity(256);

    // Control: hash_type SIGHASH_DEFAULT
    sig_msg.push(0x00u8);

    // Transaction: nVersion, nLockTime
    let mut ver_buf = [0u8; 4];
    LittleEndian::write_u32(&mut ver_buf, version);
    sig_msg.extend_from_slice(&ver_buf);
    let mut lt_buf = [0u8; 4];
    LittleEndian::write_u32(&mut lt_buf, locktime);
    sig_msg.extend_from_slice(&lt_buf);

    // sha_prevouts (single input)
    let prevouts = serialize_prevout(&input.prev_out_txid, input.prev_out_vout);
    let sha_prevouts = Sha256Hash::hash(&prevouts);
    sig_msg.extend_from_slice(&sha_prevouts.to_byte_array());

    // sha_amounts (single spent output amount)
    let mut amounts = [0u8; 8];
    LittleEndian::write_u64(&mut amounts, parent_amount);
    let sha_amounts = Sha256Hash::hash(&amounts);
    sig_msg.extend_from_slice(&sha_amounts.to_byte_array());

    // sha_scriptpubkeys (single spent script, as in CTxOut)
    let script_ser = serialize_script_for_ctxout(parent_script_pubkey);
    let sha_scriptpubkeys = Sha256Hash::hash(&script_ser);
    sig_msg.extend_from_slice(&sha_scriptpubkeys.to_byte_array());

    // sha_sequences (single input sequence)
    let mut seqs = [0u8; 4];
    LittleEndian::write_u32(&mut seqs, input.sequence);
    let sha_sequences = Sha256Hash::hash(&seqs);
    sig_msg.extend_from_slice(&sha_sequences.to_byte_array());

    // sha_outputs (all outputs of the spending tx)
    let mut outputs_ser = Vec::new();
    for o in outputs {
        outputs_ser.extend_from_slice(&serialize_output(o.value, o.script_pubkey));
    }
    let sha_outputs = Sha256Hash::hash(&outputs_ser);
    sig_msg.extend_from_slice(&sha_outputs.to_byte_array());

    // spend_type (no annex)
    sig_msg.push(0x00u8);

    // input_index (only input is at 0)
    sig_msg.extend_from_slice(&[0u8; 4]);

    // BIP-341: Taproot sighash = hashTapSighash(0x00 || SigMsg)
    let mut payload = Vec::with_capacity(1 + sig_msg.len());
    payload.push(0x00u8);
    payload.extend_from_slice(&sig_msg);
    tagged_hash(TAP_SIGHASH_TAG, &payload)
}
