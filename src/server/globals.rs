// src/server/globals.rs
//! Global server component management.
//!
//! This module provides access to globally shared components
//! using thread-safe Once Cell patterns for efficient
//! access across the application.

use std::sync::Arc;
use tokio::sync::Mutex;
use once_cell::sync::OnceCell;
use tracing::{debug, warn};

use crate::server::session::SessionManager;
use crate::crypto::session::SessionKeyManager;

/// Global TUN device instance
static TUN_DEVICE: OnceCell<Arc<Mutex<tun::platform::Device>>> = OnceCell::new();

/// Global session manager instance
static SESSION_MANAGER: OnceCell<Arc<SessionManager>> = OnceCell::new();

/// Global session key manager instance
static SESSION_KEY_MANAGER: OnceCell<Arc<SessionKeyManager>> = OnceCell::new();

/// Set the global TUN device
///
/// # Arguments
///
/// * `device` - Arc wrapped and mutex protected TUN device
///
/// # Returns
///

pub fn init_globals(tun_device: Arc<Mutex<tun::platform::Device>>) {
    // Set the TUN device
    match set_tun_device(tun_device) {
        true => debug!("Global TUN device initialized successfully"),
        false => warn!("Failed to initialize global TUN device - already set")
    }
}

/// * `bool` - true if the device was set, false if already initialized
pub fn set_tun_device(device: Arc<Mutex<tun::platform::Device>>) -> bool {
    match TUN_DEVICE.set(device) {
        Ok(_) => {
            debug!("Global TUN device initialized");
            true
        }
        Err(_) => {
            warn!("Global TUN device already initialized");
            false
        }
    }
}

/// Get the global TUN device
///
/// # Returns
///
/// * `Option<Arc<Mutex<tun::platform::Device>>>` - The TUN device if initialized
pub fn get_tun_device() -> Option<Arc<Mutex<tun::platform::Device>>> {
    TUN_DEVICE.get().cloned()
}

/// Set the global session manager
///
/// # Arguments
///
/// * `manager` - Arc wrapped SessionManager
///
/// # Returns
///
/// * `bool` - true if the manager was set, false if already initialized
pub fn set_session_manager(manager: Arc<SessionManager>) -> bool {
    match SESSION_MANAGER.set(manager) {
        Ok(_) => {
            debug!("Global session manager initialized");
            true
        }
        Err(_) => {
            warn!("Global session manager already initialized");
            false
        }
    }
}

/// Get the global session manager
///
/// # Returns
///
/// * `Option<Arc<SessionManager>>` - The session manager if initialized
pub fn get_session_manager() -> Option<Arc<SessionManager>> {
    SESSION_MANAGER.get().cloned()
}

/// Set the global session key manager
///
/// # Arguments
///
/// * `manager` - Arc wrapped SessionKeyManager
///
/// # Returns
///
/// * `bool` - true if the manager was set, false if already initialized
pub fn set_session_key_manager(manager: Arc<SessionKeyManager>) -> bool {
    match SESSION_KEY_MANAGER.set(manager) {
        Ok(_) => {
            debug!("Global session key manager initialized");
            true
        }
        Err(_) => {
            warn!("Global session key manager already initialized");
            false
        }
    }
}

/// Get the global session key manager
///
/// # Returns
///
/// * `Option<Arc<SessionKeyManager>>` - The session key manager if initialized
pub fn get_session_key_manager() -> Option<Arc<SessionKeyManager>> {
    SESSION_KEY_MANAGER.get().cloned()
}

/// Check if all required global components are initialized
///
/// # Returns
///
/// * `bool` - true if all components are initialized
pub fn all_initialized() -> bool {
    TUN_DEVICE.get().is_some() &&
    SESSION_MANAGER.get().is_some() &&
    SESSION_KEY_MANAGER.get().is_some()
}

/// Release all global components (mainly for testing)
/// 
/// Note: This is unsafe in a production environment and should only
/// be used in tests or during controlled shutdown.
#[cfg(test)]
pub fn release_all() {
    // OnceCell doesn't provide a direct way to clear,
    // so we'd need a different approach for testing
    // This is a placeholder for the concept
}
