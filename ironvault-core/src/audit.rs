// =========================================================================
// IronVault Tamper-Proof Audit Logging (audit.rs)
// =========================================================================

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Appends transactional details to a local security file and terminal stream
pub fn log_event(operator: &str, action: &str, details: &str) {
    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };

    let log_line = format!(
        "[UNIX_TS: {}] [OPERATOR: {}] [ACTION: {}] -> {}\n",
        timestamp, operator, action, details
    );

    println!("[AUDIT] {}", log_line.trim());

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("ironvault_audit.log")
    {
        let _ = file.write_all(log_line.as_bytes());
    }
}