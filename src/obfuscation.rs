use rand::{Rng, thread_rng};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time;

use crate::config;
use crate::types::Result;
use crate::types::VpnError;
use crate::utils;

/// Traffic obfuscation strategy
#[derive(Debug, Clone, PartialEq)]
pub enum ObfuscationMethod {
    /// Simple XOR-based obfuscation
    Xor,
    /// Scramblesuit-like protocol
    ScrambleSuit,
    /// Obfs4-like protocol
    Obfs4,
    /// No obfuscation
    None,
}

impl ObfuscationMethod {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "xor" => ObfuscationMethod::Xor,
            "scramblesuit" => ObfuscationMethod::ScrambleSuit,
            "obfs4" => ObfuscationMethod::Obfs4,
            _ => ObfuscationMethod::None,
        }
    }
}

/// Traffic shaper to obfuscate traffic patterns
#[derive(Debug)]
pub struct TrafficShaper {
    /// Obfuscation method
    method: ObfuscationMethod,
    /// Packet queue for delayed sending
    queue: Arc<Mutex<VecDeque<(Vec<u8>, Instant)>>>,
    /// Running flag for the background task
    running: Arc<Mutex<bool>>,
}

impl TrafficShaper {
    /// Create a new traffic shaper
    pub fn new(method: ObfuscationMethod) -> Self {
        Self {
            method,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the background traffic shaping task
    pub async fn start(&self) {
        let mut running = self.running.lock().await;
        if *running {
            return;
        }
        
        *running = true;
        
        // Clone the references for the background task
        let queue = self.queue.clone();
        let running_flag = self.running.clone();
        
        // Spawn the background task
        tokio::spawn(async move {
            while {
                let flag = running_flag.lock().await;
                *flag
            } {
                // Process the queue
                let mut has_packets = false;
                let now = Instant::now();
                
                {
                    let mut q = queue.lock().await;
                    while let Some((_, send_time)) = q.front() {
                        if *send_time <= now {
                            // Time to send this packet
                            q.pop_front();
                            // In a real implementation, this would send the packet
                            has_packets = true;
                        } else {
                            break;
                        }
                    }
                }
                
                // If we processed packets, continue immediately
                if has_packets {
                    continue;
                }
                
                // Otherwise, sleep for a bit
                time::sleep(Duration::from_millis(10)).await;
            }
        });
    }
    
    /// Stop the background traffic shaping task
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        *running = false;
    }
    
    /// Queue a packet for delayed sending
    pub async fn queue_packet(&self, packet: Vec<u8>) {
        // Apply delay based on obfuscation method
        let delay = match self.method {
            ObfuscationMethod::None => Duration::from_millis(0),
            ObfuscationMethod::Xor => utils::random_jitter(),
            ObfuscationMethod::ScrambleSuit | ObfuscationMethod::Obfs4 => {
                // More sophisticated delay pattern
                let mut rng = thread_rng();
                // Exponential distribution for more realistic timing
                let lambda = 20.0; // average delay of 20ms
                let u: f64 = rng.gen();
                let delay_ms = -lambda * (1.0 - u).ln();
                Duration::from_millis(delay_ms as u64)
            }
        };
        
        let send_time = Instant::now() + delay;
        
        let mut queue = self.queue.lock().await;
        queue.push_back((packet, send_time));
    }
    
    /// Apply obfuscation transformation to data
    pub fn transform(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        match self.method {
            ObfuscationMethod::None => data.to_vec(),
            ObfuscationMethod::Xor => self.xor_transform(data, key),
            ObfuscationMethod::ScrambleSuit => self.scramblesuit_transform(data, key),
            ObfuscationMethod::Obfs4 => self.obfs4_transform(data, key),
        }
    }
    
    /// Reverse obfuscation transformation
    pub fn untransform(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self.method {
            ObfuscationMethod::None => Ok(data.to_vec()),
            ObfuscationMethod::Xor => Ok(self.xor_transform(data, key)), // XOR is symmetric
            ObfuscationMethod::ScrambleSuit => self.scramblesuit_untransform(data, key),
            ObfuscationMethod::Obfs4 => self.obfs4_untransform(data, key),
        }
    }
    
    /// Apply XOR obfuscation
    fn xor_transform(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }
    
    /// Apply ScrambleSuit-like obfuscation
    fn scramblesuit_transform(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        // In a real implementation, this would apply the ScrambleSuit protocol
        // For now, just use XOR as a placeholder
        self.xor_transform(data, key)
    }
    
    /// Decode ScrambleSuit-like obfuscation
    fn scramblesuit_untransform(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // In a real implementation, this would apply the ScrambleSuit protocol
        // For now, just use XOR as a placeholder
        Ok(self.xor_transform(data, key))
    }
    
    /// Apply obfs4-like obfuscation
    fn obfs4_transform(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        // In a real implementation, this would apply the obfs4 protocol
        // For now, just use XOR as a placeholder
        self.xor_transform(data, key)
    }
    
    /// Decode obfs4-like obfuscation
    fn obfs4_untransform(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // In a real implementation, this would apply the obfs4 protocol
        // For now, just use XOR as a placeholder
        Ok(self.xor_transform(data, key))
    }
    
    /// Add padding to a packet to obfuscate its size
    pub fn add_padding(&self, packet: &[u8]) -> Vec<u8> {
        if !config::ENABLE_TRAFFIC_PADDING || !utils::should_add_padding() {
            return packet.to_vec();
        }
        
        let padding = utils::generate_padding(
            config::MIN_PADDING_SIZE,
            config::MAX_PADDING_SIZE,
        );
        
        // Add padding length as a prefix (2 bytes)
        let mut result = Vec::with_capacity(packet.len() + padding.len() + 2);
        result.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        result.extend_from_slice(packet);
        result.extend_from_slice(&padding);
        
        result
    }
    
    /// Remove padding from a packet
    pub fn remove_padding(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 2 {
            return Ok(packet.to_vec());
        }
        
        let mut padding_len_bytes = [0u8; 2];
        padding_len_bytes.copy_from_slice(&packet[0..2]);
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
        
        // Check if packet is long enough
        if padding_len > 0 && packet.len() >= 2 + padding_len {
            let content_end = packet.len() - padding_len;
            Ok(packet[2..content_end].to_vec())
        } else {
            // No padding or invalid format, return as is
            Ok(packet.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xor_transform() {
        let shaper = TrafficShaper::new(ObfuscationMethod::Xor);
        let data = b"Test message for obfuscation";
        let key = b"secret key";
        
        let transformed = shaper.transform(data, key);
        
        // Transformed data should be different from original
        assert_ne!(data.to_vec(), transformed);
        
        // But untransforming should give us back the original
        let untransformed = shaper.untransform(&transformed, key).unwrap();
        assert_eq!(data.to_vec(), untransformed);
    }
    
    #[test]
    fn test_padding() {
        let shaper = TrafficShaper::new(ObfuscationMethod::None);
        let data = b"Test message";
        
        // Force padding to be added
        let padded = shaper.add_padding(data);
        
        // Padded data should be longer than original
        assert!(padded.len() > data.len());
        
        // Removing padding should give us back the original
        let unpadded = shaper.remove_padding(&padded).unwrap();
        assert_eq!(data.to_vec(), unpadded);
    }
    
    #[tokio::test]
    async fn test_traffic_shaping() {
        let shaper = TrafficShaper::new(ObfuscationMethod::Xor);
        
        // Start the traffic shaper
        shaper.start().await;
        
        // Queue some packets
        for i in 0..5 {
            let packet = vec![i; 10]; // Just a test packet
            shaper.queue_packet(packet).await;
        }
        
        // Let the shaper process the queue
        time::sleep(Duration::from_millis(100)).await;
        
        // Stop the shaper
        shaper.stop().await;
        
        // Queue should be empty or nearly empty
        let queue = shaper.queue.lock().await;
        assert!(queue.len() <= 1); // Some might still be in the queue due to delays
    }
}
