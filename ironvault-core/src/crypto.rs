// =========================================================================
// IronVault Cryptographic & Machine Binding Engine (crypto.rs)
// =========================================================================

use sha2::{Sha256, Digest};
use std::process::Command;

/// Generates a platform-independent hardware fingerprint hash.
/// Queries motherboard UUIDs on Windows/Linux or IOPlatformExpertDevice on macOS.
pub fn get_machine_hardware_id() -> String {
    let raw_uuid = if cfg!(target_os = "windows") {
        let output = Command::new("cmd")
            .args(&["/C", "wmic csproduct get uuid"])
            .output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                text.lines()
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "win-fallback-hardware".to_string())
            }
            Err(_) => "win-fail-hardware".to_string(),
        }
    } else if cfg!(target_os = "macos") {
        let output = Command::new("sh")
            .args(&["-c", "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID"])
            .output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                text.split('"')
                    .nth(3)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "mac-fallback-hardware".to_string())
            }
            Err(_) => "mac-fail-hardware".to_string(),
        }
    } else {
        // Linux Systems
        let output = std::fs::read_to_string("/sys/class/dmi/id/product_uuid");
        match output {
            Ok(uuid) => uuid.trim().to_string(),
            Err(_) => "linux-fallback-hardware".to_string(),
        }
    };

    // Hash the raw hardware identifier with SHA-256 for secure data transmission
    let mut hasher = Sha256::new();
    hasher.update(raw_uuid.as_bytes());
    format!("{:02x}", hasher.finalize())[0..32].to_string().to_uppercase()
}

/// Performs SHA-256 salting and peppering of candidate administrative passwords.
pub fn secure_hash_password(password: &str, username: &str) -> String {
    let system_pepper = "STILLWATER_PEPPER_SECURE_VAL_2026_##";
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(username.as_bytes()); // Unique Salt
    hasher.update(system_pepper.as_bytes()); // Global system pepper
    
    hex::encode(&hasher.finalize())
}

/// Mock helper evaluating hexadecimal keys for the supervisor approval gates
pub fn verify_authority_signature(raw_hex_key: &str) -> bool {
    let key_trimmed = raw_hex_key.trim();
    if key_trimmed.len() < 32 {
        return false;
    }
    key_trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
