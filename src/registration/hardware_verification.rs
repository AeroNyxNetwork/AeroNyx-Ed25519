// src/registration/hardware_verification.rs
// AeroNyx Privacy Network - Hardware Verification Module
// Version: 1.0.0
//
// Copyright (c) 2024 AeroNyx Team
// SPDX-License-Identifier: MIT
//
// This module handles hardware fingerprint verification, change detection,
// and attestation for ensuring node authenticity.

use crate::hardware::HardwareInfo;
use crate::zkp_halo2::{generate_hardware_proof, SetupParams, Proof};
use crate::websocket_protocol::ProofData;
use super::{RegistrationManager, HardwareComponents, HardwareToleranceConfig, WebSocketMessage};
use std::collections::HashSet;
use tracing::{info, warn, error};

impl RegistrationManager {
    /// Verify hardware fingerprint with tolerance for minor changes
    pub async fn verify_hardware_fingerprint(&self) -> Result<(), String> {
        if let Some(stored_fingerprint) = &self.hardware_fingerprint {
            info!("Verifying hardware fingerprint...");
            
            let current_hardware = HardwareInfo::collect().await
                .map_err(|e| format!("Failed to collect hardware info: {}", e))?;
            let current_fingerprint = current_hardware.generate_fingerprint();
            
            info!("Hardware summary: {}", current_hardware.generate_fingerprint_summary());
            
            // Exact match - best case
            if &current_fingerprint == stored_fingerprint {
                info!("Hardware fingerprint verified successfully (exact match)");
                return Ok(());
            }
            
            // Check if we should allow minor changes
            if self.tolerance_config.allow_minor_changes {
                match self.check_hardware_similarity(&current_hardware).await {
                    Ok(similarity) => {
                        info!("Hardware similarity score: {:.2}%", similarity * 100.0);
                        
                        if similarity >= (1.0 - self.tolerance_config.max_change_percentage) {
                            warn!("Hardware has minor changes but within tolerance threshold");
                            
                            // Optionally notify about hardware changes
                            if let Err(e) = self.notify_hardware_change(&current_hardware, similarity).await {
                                warn!("Failed to notify hardware change: {}", e);
                            }
                            
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check hardware similarity: {}", e);
                    }
                }
            }
            
            error!("Hardware fingerprint verification failed");
            error!("Expected: {}...", &stored_fingerprint[..16]);
            error!("Current:  {}...", &current_fingerprint[..16]);
            
            // Provide detailed error information
            if self.tolerance_config.require_mac_match {
                if !self.has_matching_mac_addresses(&current_hardware) {
                    error!("No matching MAC addresses found - this appears to be different hardware");
                }
            }
            
            return Err("Hardware has changed beyond acceptable tolerance".to_string());
        } else {
            error!("No hardware fingerprint found in registration data");
            return Err("Missing hardware fingerprint - re-registration required".to_string());
        }
    }

    /// Check hardware similarity score
    pub(crate) async fn check_hardware_similarity(&self, current_hw: &HardwareInfo) -> Result<f32, String> {
        if let Some(stored_components) = &self.hardware_components {
            let mut match_score = 0.0;
            let mut total_components = 0.0;
            
            // Check MAC addresses
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            if !stored_components.mac_addresses.is_empty() {
                let matching_macs = stored_components.mac_addresses
                    .intersection(&current_macs)
                    .count();
                
                match_score += matching_macs as f32 / stored_components.mac_addresses.len().max(1) as f32;
                total_components += 1.0;
            }
            
            // Check system UUID
            if stored_components.system_uuid.is_some() {
                if current_hw.system_uuid == stored_components.system_uuid {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            // Check machine ID
            if stored_components.machine_id.is_some() {
                if current_hw.machine_id == stored_components.machine_id {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            // Check CPU model (if not allowed to change)
            if !self.tolerance_config.allow_cpu_change {
                if current_hw.cpu.model == stored_components.cpu_model {
                    match_score += 1.0;
                }
                total_components += 1.0;
            }
            
            if total_components > 0.0 {
                Ok(match_score / total_components)
            } else {
                Ok(0.0)
            }
        } else {
            // No detailed components stored, fall back to basic check
            Ok(0.0)
        }
    }

    /// Check if at least one MAC address matches
    pub(crate) fn has_matching_mac_addresses(&self, current_hw: &HardwareInfo) -> bool {
        if let Some(stored_components) = &self.hardware_components {
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical && iface.mac_address != "00:00:00:00:00:00")
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            !stored_components.mac_addresses.is_disjoint(&current_macs)
        } else {
            false
        }
    }

    /// Notify server about hardware changes
    pub(crate) async fn notify_hardware_change(&self, current_hw: &HardwareInfo, similarity: f32) -> Result<(), String> {
        warn!("Hardware change detected, similarity: {:.2}%", similarity * 100.0);
        
        // In a production system, this would send a notification to the server
        // For now, we just log it
        
        let changed_components = self.detect_changed_components(current_hw);
        info!("Changed components: {:?}", changed_components);
        
        Ok(())
    }

    /// Detect which hardware components have changed
    pub(crate) fn detect_changed_components(&self, current_hw: &HardwareInfo) -> Vec<String> {
        let mut changes = Vec::new();
        
        if let Some(stored) = &self.hardware_components {
            // Check MACs
            let current_macs: HashSet<String> = current_hw.network.interfaces
                .iter()
                .filter(|iface| iface.is_physical)
                .map(|iface| iface.mac_address.to_lowercase())
                .collect();
            
            if stored.mac_addresses != current_macs {
                changes.push("Network interfaces".to_string());
            }
            
            // Check system identifiers
            if stored.system_uuid != current_hw.system_uuid {
                changes.push("System UUID".to_string());
            }
            
            if stored.machine_id != current_hw.machine_id {
                changes.push("Machine ID".to_string());
            }
            
            if stored.cpu_model != current_hw.cpu.model {
                changes.push("CPU model".to_string());
            }
        }
        
        changes
    }

    /// Handle hardware attestation request
    pub async fn handle_attestation_request(
        &self,
        _challenge: Vec<u8>,
        nonce: String,
    ) -> Result<WebSocketMessage, String> {
        info!("Handling hardware attestation request");
        
        // Check if ZKP is enabled
        let zkp_params = self.zkp_params.as_ref()
            .ok_or("ZKP not initialized")?;
        
        // Collect current hardware info
        let current_hw = HardwareInfo::collect().await
            .map_err(|e| format!("Failed to collect hardware info: {}", e))?;
        
        // Load stored commitment
        let reg_data = self.load_registration_file()
            .map_err(|e| format!("Failed to load registration data: {}", e))?;
        
        let commitment_hex = reg_data.hardware_commitment
            .ok_or("No hardware commitment found in registration")?;
        
        let commitment = hex::decode(&commitment_hex)
            .map_err(|e| format!("Invalid commitment format: {}", e))?;
        
        // Verify hardware hasn't changed
        if !current_hw.verify_commitment(&commitment) {
            warn!("Hardware has changed since registration");
            // In production, this might trigger a re-registration flow
        }
        
        // Generate ZKP proof
        let proof = generate_hardware_proof(&current_hw, &commitment, zkp_params)
            .await
            .map_err(|e| format!("Failed to generate proof: {}", e))?;
        
        Ok(WebSocketMessage::HardwareAttestationProof {
            commitment: commitment_hex,
            proof: proof.data,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hardware_components_extraction() {
        let hw_info = HardwareInfo {
            hostname: "test-node".to_string(),
            cpu: crate::hardware::CpuInfo {
                cores: 4,
                model: "Intel Core i5".to_string(),
                frequency: 2400000000,
                architecture: "x86_64".to_string(),
                vendor_id: Some("GenuineIntel".to_string()),
            },
            memory: crate::hardware::MemoryInfo {
                total: 8000000000,
                available: 4000000000,
            },
            disk: crate::hardware::DiskInfo {
                total: 500000000000,
                available: 250000000000,
                filesystem: "ext4".to_string(),
            },
            network: crate::hardware::NetworkInfo {
                interfaces: vec![
                    crate::hardware::NetworkInterface {
                        name: "eth0".to_string(),
                        ip_address: "192.168.1.100".to_string(),
                        mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                        interface_type: "ethernet".to_string(),
                        is_physical: true,
                    },
                    crate::hardware::NetworkInterface {
                        name: "docker0".to_string(),
                        ip_address: "172.17.0.1".to_string(),
                        mac_address: "02:42:ac:11:00:01".to_string(),
                        interface_type: "bridge".to_string(),
                        is_physical: false,
                    },
                ],
                public_ip: "1.2.3.4".to_string(),
            },
            os: crate::hardware::OsInfo {
                os_type: "linux".to_string(),
                version: "22.04".to_string(),
                distribution: "Ubuntu".to_string(),
                kernel: "5.15.0".to_string(),
            },
            system_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            machine_id: Some("1234567890abcdef".to_string()),
            bios_info: None,
        };
        
        let components = RegistrationManager::extract_hardware_components(&hw_info);
        
        // Should only include physical MAC
        assert_eq!(components.mac_addresses.len(), 1);
        assert!(components.mac_addresses.contains("aa:bb:cc:dd:ee:ff"));
        assert!(!components.mac_addresses.contains("02:42:ac:11:00:01"));
        
        assert_eq!(components.cpu_model, "Intel Core i5");
        assert_eq!(components.system_uuid, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
        assert_eq!(components.machine_id, Some("1234567890abcdef".to_string()));
    }
}
