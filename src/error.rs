// src/error.rs

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

    /// Reconstructed VTXO ID did not match the expected ID (verification gate).
    IdMismatch,

    /// VTXO ID string could not be parsed (expected raw 64-char hex or "Hash:Index").
    InvalidVtxoIdFormat,

    /// Payload had trailing bytes after full VPackTree parse (cursor desynchronization).
    TrailingData(usize),
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
            Self::IdMismatch => write!(
                f,
                "VTXO ID mismatch: reconstructed ID does not match expected"
            ),
            Self::InvalidVtxoIdFormat => write!(
                f,
                "Invalid VTXO ID format (expected 64-char hex or Hash:Index)"
            ),
            Self::TrailingData(n) => write!(f, "Trailing data: {} bytes left after parse", n),
        }
    }
}

// Enable standard Error trait if the "std" feature is on.
#[cfg(feature = "std")]
impl std::error::Error for VPackError {}
