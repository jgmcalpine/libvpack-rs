//! BIP-341 Taproot Sighash (SigMsg + TapSighash tagged hash).
//!
//! no_std; supports hash types 0x00 (DEFAULT), 0x01 (ALL), 0x81 (ALL|ANYONECANPAY).
//! Used for GenesisItem Schnorr verification and tree-wide sighash policy audit.
//!
//! **Known limitations:**
//! - Epoch 0 only (the `0x00` byte prefixing the tagged hash payload).
//! - No annex support (`spend_type` is hardcoded to `0x00`).
//! - Single-input virtual transactions only.

use alloc::vec::Vec;

use byteorder::{ByteOrder, LittleEndian};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};

use crate::compact_size::write_compact_size;
use crate::consensus::taproot::tagged_hash;
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
    let signing_key = SigningKey::from_bytes(&key_bytes[..]).expect("fixed test key is valid");
    let sig = signing_key.sign_prehash(sighash).expect("sign");
    let pk = signing_key.verifying_key().to_bytes();
    (sig.to_bytes(), pk.into())
}

/// Verifies a 64-byte BIP-340 Schnorr signature over `msg` with the given x-only pubkey.
///
/// Uses `PrehashVerifier::verify_prehash` (not `Verifier::verify`) because BIP-340
/// verification uses the message bytes directly in the challenge hash — no extra
/// SHA-256 wrapping. The `Verifier` trait in k256 applies SHA-256 first, which is
/// incorrect for BIP-341 sighash messages that are already tagged hashes.
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
        .verify_prehash(msg, &signature)
        .map_err(|_| VPackError::InvalidSignature)
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

/// Compute BIP-341 Taproot sighash for a single-input virtual transaction.
///
/// Supports `hash_type` values:
/// - `0x00` (SIGHASH_DEFAULT): identical commitment to ALL, but hash_type byte is 0x00.
/// - `0x01` (SIGHASH_ALL): commits to all inputs and all outputs.
/// - `0x81` (SIGHASH_ALL | ANYONECANPAY): commits to all outputs but only this input.
///
/// Assumes BIP-341 **Epoch 0** and **no annex** (`spend_type = 0x00`).
pub fn taproot_sighash(
    version: u32,
    locktime: u32,
    input: &TxInPreimage,
    parent_amount: u64,
    parent_script_pubkey: &[u8],
    outputs: &[TxOutPreimage<'_>],
    hash_type: u8,
) -> [u8; 32] {
    let anyonecanpay = hash_type & 0x80 != 0;

    let mut sig_msg = Vec::with_capacity(256);

    // BIP-341 §SigMsg: hash_type (1 byte)
    sig_msg.push(hash_type);

    // BIP-341 §SigMsg: nVersion (4 bytes LE)
    let mut ver_buf = [0u8; 4];
    LittleEndian::write_u32(&mut ver_buf, version);
    sig_msg.extend_from_slice(&ver_buf);

    // BIP-341 §SigMsg: nLockTime (4 bytes LE)
    let mut lt_buf = [0u8; 4];
    LittleEndian::write_u32(&mut lt_buf, locktime);
    sig_msg.extend_from_slice(&lt_buf);

    if !anyonecanpay {
        // BIP-341 §SigMsg: sha_prevouts — SHA256 of all input outpoints
        let prevouts = serialize_prevout(&input.prev_out_txid, input.prev_out_vout);
        let sha_prevouts = Sha256Hash::hash(&prevouts);
        sig_msg.extend_from_slice(&sha_prevouts.to_byte_array());

        // BIP-341 §SigMsg: sha_amounts — SHA256 of all spent output amounts
        let mut amounts = [0u8; 8];
        LittleEndian::write_u64(&mut amounts, parent_amount);
        let sha_amounts = Sha256Hash::hash(&amounts);
        sig_msg.extend_from_slice(&sha_amounts.to_byte_array());

        // BIP-341 §SigMsg: sha_scriptpubkeys — SHA256 of all spent scriptPubKeys
        let script_ser = serialize_script_for_ctxout(parent_script_pubkey);
        let sha_scriptpubkeys = Sha256Hash::hash(&script_ser);
        sig_msg.extend_from_slice(&sha_scriptpubkeys.to_byte_array());

        // BIP-341 §SigMsg: sha_sequences — SHA256 of all input nSequence values
        let mut seqs = [0u8; 4];
        LittleEndian::write_u32(&mut seqs, input.sequence);
        let sha_sequences = Sha256Hash::hash(&seqs);
        sig_msg.extend_from_slice(&sha_sequences.to_byte_array());
    }

    // BIP-341 §SigMsg: sha_outputs — SHA256 of all outputs (for DEFAULT/ALL/ALL|ACP)
    let mut outputs_ser = Vec::new();
    for o in outputs {
        outputs_ser.extend_from_slice(&serialize_output(o.value, o.script_pubkey));
    }
    let sha_outputs = Sha256Hash::hash(&outputs_ser);
    sig_msg.extend_from_slice(&sha_outputs.to_byte_array());

    // BIP-341 §SigMsg: spend_type (no annex, no extension → 0x00)
    sig_msg.push(0x00u8);

    if anyonecanpay {
        // BIP-341 §SigMsg (ANYONECANPAY): outpoint (36 bytes)
        sig_msg.extend_from_slice(&input.prev_out_txid);
        let mut vout_buf = [0u8; 4];
        LittleEndian::write_u32(&mut vout_buf, input.prev_out_vout);
        sig_msg.extend_from_slice(&vout_buf);

        // BIP-341 §SigMsg (ANYONECANPAY): amount (8 bytes LE)
        let mut amt_buf = [0u8; 8];
        LittleEndian::write_u64(&mut amt_buf, parent_amount);
        sig_msg.extend_from_slice(&amt_buf);

        // BIP-341 §SigMsg (ANYONECANPAY): scriptPubKey (compact_size + script)
        write_compact_size(&mut sig_msg, parent_script_pubkey.len() as u64);
        sig_msg.extend_from_slice(parent_script_pubkey);

        // BIP-341 §SigMsg (ANYONECANPAY): nSequence (4 bytes LE)
        let mut seq_buf = [0u8; 4];
        LittleEndian::write_u32(&mut seq_buf, input.sequence);
        sig_msg.extend_from_slice(&seq_buf);
    } else {
        // BIP-341 §SigMsg: input_index (4 bytes LE, always 0 for single-input)
        sig_msg.extend_from_slice(&[0u8; 4]);
    }

    // BIP-341: TapSighash = taggedHash("TapSighash", 0x00 || SigMsg)
    // The leading 0x00 is the Epoch 0 marker.
    let mut payload = Vec::with_capacity(1 + sig_msg.len());
    payload.push(0x00u8);
    payload.extend_from_slice(&sig_msg);
    tagged_hash(TAP_SIGHASH_TAG, &payload)
}

// ---------------------------------------------------------------------------
// Allowed SIGHASH flags for tree-wide policy audit
// ---------------------------------------------------------------------------

const SIGHASH_DEFAULT: u8 = 0x00;
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_ALL_ANYONECANPAY: u8 = 0x81;

fn is_allowed_sighash_flag(flag: u8) -> bool {
    matches!(
        flag,
        SIGHASH_DEFAULT | SIGHASH_ALL | SIGHASH_ALL_ANYONECANPAY
    )
}

// ---------------------------------------------------------------------------
// Tree-wide SIGHASH policy audit
// ---------------------------------------------------------------------------

/// Walks every `GenesisItem` in the tree path, validates each sighash flag against
/// a strict allow-list, and verifies BIP-341 Taproot signatures using sequentially
/// reconstructed prevouts.
///
/// The `anchor_value` and `anchor_script` describe the on-chain UTXO that the
/// root transaction spends (the L1 anchor). The auditor uses them as the initial
/// prevout context, then derives subsequent prevouts from each reconstructed
/// virtual transaction.
///
/// # Errors
///
/// - [`VPackError::InvalidSighashFlag`] if a flag is not in `{0x00, 0x01, 0x81}`.
/// - [`VPackError::InvalidSignature`] if any Schnorr signature fails verification.
/// - [`VPackError::EncodingError`] if output reconstruction fails.
pub fn audit_sighash_policy(
    tree: &crate::payload::tree::VPackTree,
    variant: crate::header::TxVariant,
    anchor_value: u64,
    anchor_script: &[u8],
) -> Result<(), VPackError> {
    use crate::consensus::tx_factory::tx_preimage;
    use crate::payload::tree::SiblingNode;
    use crate::types::hashes::sha256d;

    let mut current_txid = tree.anchor.txid.to_byte_array();
    let mut current_vout = tree.anchor.vout;
    let mut current_prevout_value = anchor_value;
    let mut current_prevout_script: Vec<u8> = anchor_script.to_vec();

    for (i, genesis_item) in tree.path.iter().enumerate() {
        // --- Policy filter: reject disallowed sighash types early ---
        if !is_allowed_sighash_flag(genesis_item.sighash_flag) {
            return Err(VPackError::InvalidSighashFlag(genesis_item.sighash_flag));
        }

        // --- Reconstruct outputs (variant-specific) ---
        let outputs: Vec<TxOutPreimage<'_>> = match variant {
            crate::header::TxVariant::V3Anchored => {
                let mut outs = Vec::new();
                if !genesis_item.child_script_pubkey.is_empty() {
                    outs.push(TxOutPreimage {
                        value: genesis_item.child_amount,
                        script_pubkey: genesis_item.child_script_pubkey.as_slice(),
                    });
                }
                for sibling in &genesis_item.siblings {
                    match sibling {
                        SiblingNode::Compact { value, script, .. } => {
                            outs.push(TxOutPreimage {
                                value: *value,
                                script_pubkey: script.as_slice(),
                            });
                        }
                        SiblingNode::Full(_) => return Err(VPackError::EncodingError),
                    }
                }
                outs
            }
            crate::header::TxVariant::V3Plain => {
                crate::consensus::second_tech::SecondTechV3::reconstruct_link(genesis_item)?
            }
        };

        // --- Build input spending the current prevout ---
        let input = TxInPreimage {
            prev_out_txid: current_txid,
            prev_out_vout: current_vout,
            sequence: genesis_item.sequence,
        };

        // --- Signature verification ---
        if let Some(ref sig) = genesis_item.signature {
            let verify_key =
                extract_verify_key(&current_prevout_script).ok_or(VPackError::InvalidSignature)?;
            let sighash = taproot_sighash(
                3,
                0,
                &input,
                current_prevout_value,
                &current_prevout_script,
                &outputs,
                genesis_item.sighash_flag,
            );
            verify_schnorr_bip340(&verify_key, &sighash, sig)?;
        }

        // --- Compute txid for hand-off to next depth ---
        let preimage_bytes = tx_preimage(3, &[input], &outputs, 0);
        let hash = sha256d::Hash::hash(&preimage_bytes);
        current_txid = hash.to_byte_array();

        // --- Determine next prevout vout ---
        let next_vout = match variant {
            crate::header::TxVariant::V3Anchored => 0u32,
            crate::header::TxVariant::V3Plain => {
                if i + 1 < tree.path.len() {
                    tree.path[i + 1].parent_index
                } else {
                    tree.leaf.vout
                }
            }
        };

        // --- Update prevout state for next iteration ---
        let vout_idx = next_vout as usize;
        if vout_idx >= outputs.len() {
            return Err(VPackError::InvalidVout(next_vout));
        }
        current_prevout_value = outputs[vout_idx].value;
        current_prevout_script = outputs[vout_idx].script_pubkey.to_vec();
        current_vout = next_vout;
    }

    Ok(())
}
