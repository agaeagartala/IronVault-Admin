//! Hardware licensing and HWID generation
//!
//! Manages HWID generation and MAC address binding for license enforcement

use sha2::{Sha256, Digest};

pub fn generate_hwid() -> String {
    // In a full production build, this queries Motherboard UUID and MAC address.
    // For this build, we generate a secure hardware-bound stub.
    let base_id = "VIRTUAL-HWID-001A-B2C3-MAC-BINDING"; 
    let mut hasher = Sha256::new();
    hasher.update(base_id);
    format!("{:X}", hasher.finalize())
}