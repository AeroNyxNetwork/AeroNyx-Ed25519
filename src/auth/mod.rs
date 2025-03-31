// src/auth/mod.rs
//! Authentication module for the AeroNyx Privacy Network Server.
//!
//! This module provides authentication and access control functionality
//! for client connections.

pub mod acl;
pub mod challenge;
pub mod manager;

// Re-export commonly used items
pub use acl::AccessControlList;
// Removed unused Challenge, ChallengeManager exports (assuming they are only used internally or via AuthManager)
pub use manager::AuthManager;
