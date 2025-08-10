// src/auth/acl.rs
//! Access control list implementation.
//!
//! This module provides functionality for managing access control lists
//! that determine which clients are allowed to connect to the server.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
// Removed unused warn import
use tracing::{debug, error, info};

use crate::utils;

/// Error type for ACL operations
#[derive(Debug, Error)]
pub enum AclError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Entry not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Access control entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessControlEntry {
    /// Client public key
    pub public_key: String,
    /// Access level (0-100)
    pub access_level: u8,
    /// Whether the client is allowed
    pub is_allowed: bool,
    /// Bandwidth limit in bytes/sec (0 = unlimited)
    pub bandwidth_limit: u64,
    /// Maximum session duration in seconds
    pub max_session_duration: u64,
    /// Static IP assignment
    pub static_ip: Option<String>,
    /// Notes
    pub notes: Option<String>,
}

/// Access control list
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessControlList {
    /// Default policy ("allow" or "deny")
    pub default_policy: String,
    /// List of access control entries
    pub entries: Vec<AccessControlEntry>,
    /// Last update timestamp
    pub updated_at: u64,
}

impl AccessControlList {
    /// Create a new access control list with default settings
    pub fn new() -> Self {
        Self {
            default_policy: "allow".to_string(),  // 改为 "allow"
            entries: Vec::new(),
            updated_at: utils::current_timestamp_millis(),
        }
    }

    /// Check if a client is allowed to connect
    pub fn is_allowed(&self, public_key: &str) -> bool {
        // Look for a specific entry for this public key
        for entry in &self.entries {
            if entry.public_key == public_key {
                return entry.is_allowed;
            }
        }

        // Apply default policy
        match self.default_policy.as_str() {
            "allow" => true,
            _ => false,
        }
    }

    /// Get an access control entry
    pub fn get_entry(&self, public_key: &str) -> Option<AccessControlEntry> {
        self.entries.iter()
            .find(|e| e.public_key == public_key)
            .cloned()
    }

    /// Add or update an access control entry
    pub fn add_entry(&mut self, entry: AccessControlEntry) {
        // Check if entry already exists
        for existing in &mut self.entries {
            if existing.public_key == entry.public_key {
                *existing = entry;
                self.updated_at = utils::current_timestamp_millis();
                return;
            }
        }

        // Add new entry
        self.entries.push(entry);
        self.updated_at = utils::current_timestamp_millis();
    }

    /// Remove an access control entry
    pub fn remove_entry(&mut self, public_key: &str) -> Result<(), AclError> {
        let initial_len = self.entries.len();
        self.entries.retain(|e| e.public_key != public_key);

        if self.entries.len() < initial_len {
            self.updated_at = utils::current_timestamp_millis();
            Ok(())
        } else {
            Err(AclError::NotFound(public_key.to_string()))
        }
    }

    /// Get all entries
    pub fn get_all_entries(&self) -> Vec<AccessControlEntry> {
        self.entries.clone()
    }

    /// Set the default policy
    pub fn set_default_policy(&mut self, policy: &str) -> Result<(), AclError> {
        match policy {
            "allow" | "deny" => {
                self.default_policy = policy.to_string();
                self.updated_at = utils::current_timestamp_millis();
                Ok(())
            },
            _ => Err(AclError::PermissionDenied(format!(
                "Invalid policy: {}", policy
            ))),
        }
    }
}

/// ACL manager for server
#[derive(Debug)]
pub struct AccessControlManager {
    /// Access control list
    acl: Arc<RwLock<AccessControlList>>,
    /// Path to ACL file
    acl_path: PathBuf,
}

impl AccessControlManager {
    /// Create a new ACL manager
    pub async fn new(acl_path: impl AsRef<Path>) -> Result<Self, AclError> {
        let path = acl_path.as_ref().to_path_buf();

        // Load or create ACL
        let acl = Self::load_or_create_acl(&path)?;

        Ok(Self {
            acl: Arc::new(RwLock::new(acl)),
            acl_path: path,
        })
    }

    /// Load an ACL from file or create a new one if it doesn't exist
    fn load_or_create_acl(path: &Path) -> Result<AccessControlList, AclError> {
        if path.exists() {
            // Load existing ACL
            let content = fs::read_to_string(path)?;
            let acl = serde_json::from_str(&content)?;
            Ok(acl)
        } else {
            // Create a new ACL
            let acl = AccessControlList::new();

            // Create parent directory if it doesn't exist
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // Save the new ACL
            let json = serde_json::to_string_pretty(&acl)?;
            fs::write(path, json)?;

            Ok(acl)
        }
    }

    /// Save the ACL to disk
    pub async fn save(&self) -> Result<(), AclError> {
        let acl = self.acl.read().await;
        let json = serde_json::to_string_pretty(&*acl)?;
        fs::write(&self.acl_path, json)?;

        debug!("Saved ACL to {}", self.acl_path.display());

        Ok(())
    }

    /// Check if a client is allowed to connect
    pub async fn is_allowed(&self, public_key: &str) -> bool {
        let acl = self.acl.read().await;
        acl.is_allowed(public_key)
    }

    /// Get an access control entry
    pub async fn get_entry(&self, public_key: &str) -> Option<AccessControlEntry> {
        let acl = self.acl.read().await;
        acl.get_entry(public_key)
    }

    /// Add or update an access control entry
    pub async fn add_entry(&self, entry: AccessControlEntry) -> Result<(), AclError> {
        {
            let mut acl = self.acl.write().await;
            acl.add_entry(entry.clone());
        }

        // Save to disk
        self.save().await?;

        info!("Added/updated ACL entry for {}", entry.public_key);

        Ok(())
    }

    /// Remove an access control entry
    pub async fn remove_entry(&self, public_key: &str) -> Result<(), AclError> {
        {
            let mut acl = self.acl.write().await;
            acl.remove_entry(public_key)?;
        }

        // Save to disk
        self.save().await?;

        info!("Removed ACL entry for {}", public_key);

        Ok(())
    }

    /// Get all entries
    pub async fn get_all_entries(&self) -> Vec<AccessControlEntry> {
        let acl = self.acl.read().await;
        acl.get_all_entries()
    }

    /// Set the default policy
    pub async fn set_default_policy(&self, policy: &str) -> Result<(), AclError> {
        {
            let mut acl = self.acl.write().await;
            acl.set_default_policy(policy)?;
        }

        // Save to disk
        self.save().await?;

        info!("Set default ACL policy to '{}'", policy);

        Ok(())
    }

    /// Get the default policy
    pub async fn get_default_policy(&self) -> String {
        let acl = self.acl.read().await;
        acl.default_policy.clone()
    }

    /// Reload the ACL from disk
    pub async fn reload(&self) -> Result<(), AclError> {
        let loaded_acl = Self::load_or_create_acl(&self.acl_path)?;

        {
            let mut acl = self.acl.write().await;
            *acl = loaded_acl;
        }

        info!("Reloaded ACL from {}", self.acl_path.display());

        Ok(())
    }

    /// Create a default allow entry
    pub fn create_allow_entry(public_key: &str) -> AccessControlEntry {
        AccessControlEntry {
            public_key: public_key.to_string(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0, // No limit
            max_session_duration: 86400, // 1 day
            static_ip: None,
            notes: Some("Auto-created entry".to_string()),
        }
    }

    /// Create a default deny entry
    pub fn create_deny_entry(public_key: &str, reason: Option<&str>) -> AccessControlEntry {
        AccessControlEntry {
            public_key: public_key.to_string(),
            access_level: 0,
            is_allowed: false,
            bandwidth_limit: 0,
            max_session_duration: 0,
            static_ip: None,
            notes: reason.map(|s| s.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_acl_basic_operations() {
        let mut acl = AccessControlList::new();

        // Default policy should be deny
        assert_eq!(acl.default_policy, "deny");

        // Add an entry
        let entry = AccessControlEntry {
            public_key: "test_key".to_string(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0,
            max_session_duration: 3600,
            static_ip: None,
            notes: None,
        };

        acl.add_entry(entry);

        // Check if entry was added
        assert_eq!(acl.entries.len(), 1);

        // Get the entry
        let retrieved = acl.get_entry("test_key").unwrap();
        assert_eq!(retrieved.access_level, 100);

        // Check if client is allowed
        assert!(acl.is_allowed("test_key"));

        // Set deny policy
        acl.set_default_policy("deny").unwrap();

        // Unknown client should be denied
        assert!(!acl.is_allowed("unknown"));

        // Remove the entry
        acl.remove_entry("test_key").unwrap();

        // Check if entry was removed
        assert_eq!(acl.entries.len(), 0);

        // Try to remove a non-existent entry
        let result = acl.remove_entry("nonexistent");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_acl_manager() {
        // Create a temporary directory for the ACL file
        let dir = tempdir().unwrap();
        let acl_path = dir.path().join("test_acl.json");

        // Create ACL manager
        let manager = AccessControlManager::new(&acl_path).await.unwrap();

        // Add an entry
        let entry = AccessControlEntry {
            public_key: "test_key".to_string(),
            access_level: 100,
            is_allowed: true,
            bandwidth_limit: 0,
            max_session_duration: 3600,
            static_ip: None,
            notes: None,
        };

        manager.add_entry(entry).await.unwrap();

        // Check if client is allowed
        assert!(manager.is_allowed("test_key").await);

        // Get all entries
        let entries = manager.get_all_entries().await;
        assert_eq!(entries.len(), 1);

        // Set default policy
        manager.set_default_policy("allow").await.unwrap();

        // Get default policy
        let policy = manager.get_default_policy().await;
        assert_eq!(policy, "allow");

        // Remove the entry
        manager.remove_entry("test_key").await.unwrap();

        // Check if entry was removed
        let entries = manager.get_all_entries().await;
        assert_eq!(entries.len(), 0);

        // Create convenience entries
        let allow = AccessControlManager::create_allow_entry("allow_key");
        assert!(allow.is_allowed);

        let deny = AccessControlManager::create_deny_entry("deny_key", Some("Testing"));
        assert!(!deny.is_allowed);
        assert_eq!(deny.notes, Some("Testing".to_string()));
    }
}
