#![no_std]

#[cfg(feature = "std")]
extern crate std;

// Needed for Vec
#[macro_use]
extern crate alloc;

pub mod error;
pub mod header;
pub mod pack;
pub mod payload;
// pub mod consensus;

pub use header::TxVariant;