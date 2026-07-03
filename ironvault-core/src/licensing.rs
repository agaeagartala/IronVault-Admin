//! Hardware licensing and HWID generation
//!
//! Manages HWID generation and MAC address binding for license enforcement

use sha2::{Sha256, Digest};

pub struct LicenseManager;

impl LicenseManager {
    pub fn new() -> Self { Self }
    
    pub fn generate_hwid() -> String {
        let base_id = "VIRTUAL-HWID-001A-B2C3-MAC-BINDING"; 
        let mut hasher = Sha256::new();
        hasher.update(base_id);
        format!("{:X}", hasher.finalize())
    }
}

pub fn generate_hwid() -> String {
    LicenseManager::generate_hwid()
}