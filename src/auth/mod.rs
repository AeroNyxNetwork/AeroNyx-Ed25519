// src/auth/mod.rs
//! Authentication module for the AeroNyx Privacy Network Server.
//!
//! This module provides authentication and access control functionality
//! for client connections.

pub mod acl;
pub mod challenge;
pub mod manager;

// Re-export commonly used items
// Removed unused AccessControlList re-export (it's used internally via manager)
// pub use acl::AccessControlList;
// Removed unused ChallengeManager re-export
// pub use challenge::{Challenge, ChallengeManager};
pub use manager::AuthManager;
