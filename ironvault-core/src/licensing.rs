//! Hardware licensing and HWID generation
//!
//! Derives a stable per-machine identifier from actual OS-level hardware/installation
//! identifiers, so that a login can be meaningfully bound "to this machine."
//!
//! IMPORTANT: the previous implementation hashed a hardcoded string literal, which
//! produces the exact same HWID on every machine that ever runs the binary — making
//! the hardware-binding check in `postgres.rs::authenticate_user` a no-op. This
//! version pulls from real, OS-specific stable identifiers instead.

use sha2::{Digest, Sha256};

pub struct LicenseManager;

impl LicenseManager {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_hwid() -> String {
        let raw_id = Self::collect_raw_machine_identifiers();

        let mut hasher = Sha256::new();
        hasher.update(raw_id.as_bytes());
        format!("{:X}", hasher.finalize())
    }

    /// Gathers whatever stable, OS-specific identifiers are available on this platform
    /// and concatenates them into one raw string before hashing. Falls back gracefully
    /// (rather than panicking) if a given source isn't readable, but always logs when
    /// it has to fall back so a misconfigured/locked-down environment is visible.
    fn collect_raw_machine_identifiers() -> String {
        let mut parts: Vec<String> = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
                parts.push(machine_id.trim().to_string());
            } else if let Ok(dbus_id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
                parts.push(dbus_id.trim().to_string());
            }
            if let Ok(product_uuid) =
                std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
            {
                parts.push(product_uuid.trim().to_string());
            }
        }

        #[cfg(target_os = "windows")]
        {
            // MachineGuid is written once at OS install time and persists across
            // reboots/reinstalls of any given application, making it a solid anchor.
            if let Some(guid) = Self::read_windows_machine_guid() {
                parts.push(guid);
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Some(uuid) = Self::read_macos_hardware_uuid() {
                parts.push(uuid);
            }
        }

        if parts.is_empty() {
            // Genuine fallback path: no OS-level identifier could be read (e.g. sandboxed
            // container, locked-down permissions). Log loudly — this is a security-relevant
            // degradation, not a silent default — and fall back to a random-but-persisted
            // identifier instead of a hardcoded constant, so at least different installs
            // still get different HWIDs even in this degraded case.
            log::warn!(
                "[LICENSING] No OS-level machine identifier could be read; \
                 falling back to a persisted random identifier. HWID binding \
                 will be weaker than normal on this host."
            );
            parts.push(Self::persisted_fallback_identifier());
        }

        parts.join("|")
    }

    #[cfg(target_os = "windows")]
    fn read_windows_machine_guid() -> Option<String> {
        // Reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid via the `reg` query
        // command to avoid pulling in a full registry-access crate for one value.
        // (Swap for the `winreg` crate directly if you'd rather avoid shelling out.)
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find(|l| l.contains("MachineGuid"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
    }

    #[cfg(target_os = "macos")]
    fn read_macos_hardware_uuid() -> Option<String> {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;

        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find(|l| l.contains("IOPlatformUUID"))
            .and_then(|l| l.split('"').nth(3))
            .map(|s| s.to_string())
    }

    /// Last-resort fallback: a random identifier generated once and cached to disk,
    /// so repeated calls on the same (unreadable-hardware) machine are at least
    /// stable across app restarts, rather than a compile-time constant shared by
    /// every install everywhere.
    fn persisted_fallback_identifier() -> String {
        use rand::RngCore;
        use std::io::Write;

        let fallback_path = std::path::Path::new("./storage/.hwid_fallback");

        if let Ok(existing) = std::fs::read_to_string(fallback_path) {
            let trimmed = existing.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }

        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let generated = hex::encode(bytes);

        if let Some(parent) = fallback_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::File::create(fallback_path) {
            let _ = file.write_all(generated.as_bytes());
        }

        generated
    }
}

pub fn generate_hwid() -> String {
    LicenseManager::generate_hwid()
}