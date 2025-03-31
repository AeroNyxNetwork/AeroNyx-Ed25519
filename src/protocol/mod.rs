// src/protocol/mod.rs
//! Protocol module for the AeroNyx Privacy Network Server.
//!
//! This module defines the protocol messages and types used for
//! client-server communication.

pub mod types;
pub mod serialization;
pub mod validation;

// Re-export commonly used items
pub use types::{PacketType, MessageError};
// Removed unused validate_message re-export (assuming it's used internally via serialization)
// pub use validation::validate_message; // Remove if not needed externally
