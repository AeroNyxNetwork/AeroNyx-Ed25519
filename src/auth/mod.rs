// src/auth/mod.rs
//! Authentication module for the AeroNyx Privacy Network Server.
//!
//! This module provides authentication and access control functionality
//! for client connections.

pub mod acl;
pub mod challenge;
pub mod manager;

// Re-export commonly used items
// Removed unused AccessControlList import (assuming manager is used)
pub use challenge::{Challenge, ChallengeManager}; // Kept ChallengeManager
// Removed unused Challenge import if only manager is needed externally
pub use manager::AuthManager;
