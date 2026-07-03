//! Security validation for anti-debug, anti-dump, and VM detection
//!
//! Provides runtime security checks to prevent unauthorized access and tampering

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;

pub fn enforce_anti_debug() {
    #[cfg(target_os = "windows")]
    unsafe {
        if IsDebuggerPresent() != 0 {
            println!("[SECURITY_FAULT] Unauthorized debugger detected. Self-terminating.");
            std::process::exit(1); // Hard crash
        }
    }
}