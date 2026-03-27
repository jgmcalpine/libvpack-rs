// src/error.rs

use core::fmt;

/// Writes a 32-byte value as a full 64-character lowercase hex string (forensic / audit output).
pub(crate) fn fmt_hash32_full(f: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for b in bytes {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}

/// Why [`VPackError::TimelockViolation`] was raised (BIP-68 CSV / BIP-113 CLTV audit).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimelockViolationReason {
    /// BIP-68: `nSequence` magnitude (lower 16 bits) or absolute locktime is below the script.
    ValueTooLow,
    /// Block-height vs timestamp units disagree between script and packaged field (BIP-68 type bit
    /// or BIP-113 height vs time).
    TypeMismatch,
    /// BIP-68: `SEQUENCE_LOCKTIME_DISABLE_FLAG` (bit 31) is set while a CSV requirement exists.
    LocktimeDisabled,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VPackError {
    /// The data stream ended before the header or payload could be fully read.
    IncompleteData,

    /// The Magic Bytes were not 'VPK'.
    InvalidMagic,

    /// The Header Version is not supported by this library (currently only V1).
    UnsupportedVersion(u8),

    /// Tree Arity must be >= 2. (0 or 1 creates invalid/degenerate trees).
    InvalidArity(u16),

    /// The Payload length was 0.
    EmptyPayload,

    /// The Payload length exceeded the software limit (1MB).
    PayloadTooLarge(u32),

    /// The Tree Depth exceeded the Header limit (32).
    ExceededMaxDepth(u16),

    /// The Tree Arity exceeded the Header limit (16).
    ExceededMaxArity(u16),

    /// The claimed Node Count is mathematically impossible for the given Depth/Arity.
    /// (Actual Count, Theoretical Max)
    NodeCountMismatch(u16, u16),

    /// Checksum verification failed (CRC32 mismatch).
    ChecksumMismatch { expected: u32, found: u32 },

    /// Generic encoding/decoding error (Borsh failure).
    EncodingError,

    /// Tx Variant byte was not 0x03 (V3-Plain) or 0x04 (V3-Anchored).
    InvalidTxVariant(u8),

    /// Sequence was not 0xFFFFFFFF (Round) or 0xFFFFFFFE (OOR) where required.
    SequenceMismatch(u32),

    /// V3-Anchored (0x04) requires a non-empty fee anchor script.
    FeeAnchorMissing,

    /// Invalid or out-of-range vout (e.g. for OutPoint-based IDs).
    InvalidVout(u32),

    /// Policy invariant violated (fee_anchor, sequence, or exit_delta inconsistency).
    PolicyMismatch,

    /// Reconstructed VTXO ID did not match the expected ID (verification gate).
    ///
    /// `computed` / `expected` are **internal wire-order** bytes: the raw VTXO hash for
    /// [`crate::consensus::VtxoId::Raw`], or the **txid** for [`crate::consensus::VtxoId::OutPoint`].
    /// `computed_vout` / `expected_vout` are `Some` only for [`crate::consensus::VtxoId::OutPoint`]
    /// (Second Tech); [`Display`](core::fmt::Display) prints them so txid-only equality cannot hide a vout bug.
    IdMismatch {
        computed: [u8; 32],
        expected: [u8; 32],
        computed_vout: Option<u32>,
        expected_vout: Option<u32>,
    },

    /// Output sum did not equal input amount (conservation of value); or overflow when summing outputs.
    ValueMismatch { expected: u64, actual: u64 },

    /// VTXO ID string could not be parsed (expected raw 64-char hex or "Hash:Index").
    InvalidVtxoIdFormat,

    /// Payload had trailing bytes after full VPackTree parse (cursor desynchronization).
    TrailingData(usize),

    /// A GenesisItem signature failed Taproot (BIP-340/341) verification.
    InvalidSignature,

    /// The sighash flag on a GenesisItem is not in the allowed policy set
    /// {0x00 (DEFAULT), 0x01 (ALL), 0x81 (ALL|ANYONECANPAY)}.
    InvalidSighashFlag(u8),

    /// Bark script template failed zero-trust validation (CLTV expiry or unlock clause).
    InvalidBarkScript,

    /// Ark Labs tapscript template failed zero-trust validation (forfeit or exit clause).
    InvalidArkLabsScript,

    /// Path exclusivity data (internal_key + asp_expiry_script) is missing from the tree.
    MissingExclusivityData,

    /// Derived Taproot tweaked key does not match the x-only key in the leaf P2TR scriptPubKey.
    PathExclusivityViolation {
        derived_key: [u8; 32],
        expected_key: [u8; 32],
    },

    /// BIP-341 control block could not be reconstructed from the tree (no matching Taproot layout).
    ControlBlockReconstructionFailed,

    /// Transaction timelock does not satisfy `asp_expiry_script` (BIP-68 / BIP-113).
    ///
    /// `expected` / `actual` are the script threshold vs observed packaged value (for CSV, often
    /// lower 16 bits of `nSequence`); `is_relative` is `true` for CSV, `false` for CLTV.
    TimelockViolation {
        expected: u32,
        actual: u32,
        is_relative: bool,
        reason: TimelockViolationReason,
    },

    /// Parsed tree is missing data required for the checked completeness policy.
    ///
    /// **Depth convention:** `0` always refers to the **leaf tier** (the VTXO leaf script and/or
    /// `leaf_siblings` entries). Values `1..=N` refer to **path steps** counting **upward from the
    /// leaf** (`1` = first [`GenesisItem`](crate::payload::tree::GenesisItem) after the leaf,
    /// i.e. index `0` in `tree.path`).
    TreeIncomplete { depth: u16, field: &'static str },
}

// Manual implementation of Display for no_std environments.
impl core::fmt::Display for VPackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IncompleteData => write!(f, "Incomplete V-PACK data"),
            Self::InvalidMagic => write!(f, "Invalid Magic Bytes"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported Protocol Version: {}", v),
            Self::InvalidArity(a) => write!(f, "Invalid Arity: {} (Must be >= 2)", a),
            Self::EmptyPayload => write!(f, "Payload is empty"),
            Self::PayloadTooLarge(s) => write!(f, "Payload too large: {} bytes", s),
            Self::ExceededMaxDepth(d) => write!(f, "Tree Depth {} exceeds limit", d),
            Self::ExceededMaxArity(a) => write!(f, "Tree Arity {} exceeds limit", a),
            Self::NodeCountMismatch(count, limit) => {
                write!(f, "Node count {} exceeds theoretical max {}", count, limit)
            }
            Self::ChecksumMismatch { expected, found } => write!(
                f,
                "Checksum mismatch: expected {:08x}, found {:08x}",
                expected, found
            ),
            Self::EncodingError => write!(f, "Binary encoding/decoding error"),
            Self::InvalidTxVariant(v) => {
                write!(f, "Invalid Tx Variant: 0x{:02x} (expected 0x03 or 0x04)", v)
            }
            Self::SequenceMismatch(s) => write!(
                f,
                "Sequence mismatch: 0x{:08x} (expected 0xFFFFFFFF or 0xFFFFFFFE)",
                s
            ),
            Self::FeeAnchorMissing => {
                write!(f, "Fee anchor script missing (required for V3-Anchored)")
            }
            Self::InvalidVout(v) => write!(f, "Invalid vout: {}", v),
            Self::PolicyMismatch => write!(
                f,
                "Policy invariant violated (fee_anchor, sequence, or exit_delta inconsistency)"
            ),
            Self::IdMismatch {
                computed,
                expected,
                computed_vout,
                expected_vout,
            } => {
                write!(f, "VTXO ID mismatch: computed ")?;
                fmt_hash32_full(f, computed)?;
                if let Some(v) = computed_vout {
                    write!(f, ":{}", v)?;
                }
                write!(f, ", expected ")?;
                fmt_hash32_full(f, expected)?;
                if let Some(v) = expected_vout {
                    write!(f, ":{}", v)?;
                }
                if computed == expected {
                    if let (Some(cv), Some(ev)) = (computed_vout, expected_vout) {
                        if cv != ev {
                            write!(
                                f,
                                " (identical 32-byte id bytes; vout differs: computed {cv}, expected {ev})"
                            )?;
                        }
                    }
                }
                Ok(())
            }
            Self::ValueMismatch { expected, actual } => {
                let delta = i128::from(*expected) - i128::from(*actual);
                write!(
                    f,
                    "Value mismatch: expected {} sats from anchor/parent, outputs sum to {} (expected - actual = {} sats",
                    expected, actual, delta
                )?;
                if delta > 0 {
                    write!(f, "; outputs short by {} sats)", delta)
                } else if delta < 0 {
                    write!(f, "; outputs exceed by {} sats)", -delta)
                } else {
                    write!(f, ")")
                }
            }
            Self::InvalidVtxoIdFormat => write!(
                f,
                "Invalid VTXO ID format (expected 64-char hex or Hash:Index)"
            ),
            Self::TrailingData(n) => write!(f, "Trailing data: {} bytes left after parse", n),
            Self::InvalidSignature => write!(
                f,
                "Invalid signature: GenesisItem Schnorr signature verification failed"
            ),
            Self::InvalidSighashFlag(flag) => write!(
                f,
                "Invalid sighash flag: 0x{:02x} (allowed: 0x00, 0x01, 0x81)",
                flag
            ),
            Self::InvalidBarkScript => write!(
                f,
                "Invalid Bark script template (CLTV expiry or unlock clause)"
            ),
            Self::InvalidArkLabsScript => write!(
                f,
                "Invalid Ark Labs tapscript template (forfeit or exit clause)"
            ),
            Self::MissingExclusivityData => write!(
                f,
                "Path exclusivity data missing: internal_key and asp_expiry_script are required"
            ),
            Self::PathExclusivityViolation {
                derived_key,
                expected_key,
            } => {
                write!(
                    f,
                    "Path exclusivity violation: derived Taproot output key "
                )?;
                fmt_hash32_full(f, derived_key)?;
                write!(f, " does not match scriptPubKey x-only key ")?;
                fmt_hash32_full(f, expected_key)
            }
            Self::ControlBlockReconstructionFailed => write!(
                f,
                "BIP-341 control block reconstruction failed: tree Taproot layout does not match P2TR output"
            ),
            Self::TimelockViolation {
                expected,
                actual,
                is_relative,
                reason,
            } => {
                let kind = if *is_relative {
                    "relative (CSV)"
                } else {
                    "absolute (CLTV)"
                };
                match reason {
                    TimelockViolationReason::ValueTooLow => write!(
                        f,
                        "Timelock violation ({kind}): value too low (need >= {expected}, got {actual})"
                    ),
                    TimelockViolationReason::TypeMismatch => write!(
                        f,
                        "Timelock violation ({kind}): type mismatch (script vs packaged field; expected threshold {expected}, observed {actual})"
                    ),
                    TimelockViolationReason::LocktimeDisabled => write!(
                        f,
                        "Timelock violation ({kind}): BIP-68 disable bit (31) set on nSequence 0x{actual:08x} but CSV is required"
                    ),
                }
            }
            Self::TreeIncomplete { depth, field } => {
                if *depth == 0 {
                    write!(f, "Tree incomplete at leaf tier: missing {}", field)
                } else {
                    write!(
                        f,
                        "Tree incomplete at path step {} (1-based from leaf): missing {}",
                        depth, field
                    )
                }
            }
        }
    }
}

// Enable standard Error trait if the "std" feature is on.
#[cfg(feature = "std")]
impl std::error::Error for VPackError {}
