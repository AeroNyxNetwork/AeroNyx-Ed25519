// src/registration.rs
// AeroNyx Privacy Network - Node Registration Module Entry Point
// Version: 1.0.1
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This is the main entry point for the registration module.
// It re-exports all public types and functionality from the submodules.

pub mod registration;

// Re-export everything from the registration module for backward compatibility
pub use registration::*;

// Also re-export the ClientMessage type for external use
pub use crate::websocket_protocol::ClientMessage;
