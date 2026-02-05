#![no_std]

#[cfg(feature = "std")]
extern crate std;

// Needed for Vec
extern crate alloc;

pub mod compact_size;
pub mod consensus;
pub mod error;
pub mod header;
pub mod pack;
pub mod payload;

pub use consensus::{ConsensusEngine, VtxoId};
pub use header::TxVariant;