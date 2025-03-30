// src/server/globals.rs
//! Global server variables and references.
//!
//! This module provides global access to key server components
//! for use across modules.

use std::sync::Arc;
use tokio::sync::Mutex;
use tun::platform::Device;
use once_cell::sync::OnceCell;

/// Global reference to the TUN device
pub static SERVER_TUN_DEVICE: OnceCell<Arc<Mutex<Device>>> = OnceCell::new();

/// Initialize global server components
pub fn init_globals(tun_device: Arc<Mutex<Device>>) {
    // Set global TUN device
    if SERVER_TUN_DEVICE.set(tun_device).is_err() {
        // This should only happen if init_globals is called more than once
        tracing::warn!("SERVER_TUN_DEVICE already initialized");
    }
}
