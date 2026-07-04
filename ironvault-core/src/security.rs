//! Security validation for anti-debug, anti-dump, and VM detection
//!
//! Provides runtime security checks to prevent unauthorized access and tampering

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;

use std::arch::asm;

// Idiomatic CPUID intrinsics to safely bypass LLVM rbx/ebx register constraints
#[cfg(target_arch = "x86")]
use std::arch::x86::__cpuid;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__cpuid;

/// Executes critical system checks wrapped in native VMProtect virtualization markers.
/// The post-build VMProtect scanner will detect these byte arrays and convert the enclosed
/// x86_64 instructions into randomized virtual machine bytecode.
pub fn enforce_core_security_checks(current_hwid: &str) {
    unsafe {
        // Replaced character strings with raw numerical byte literals compatible with LLVM assembler syntax
        asm!(
            ".byte 0xEB, 0x08, 0x56, 0x4D, 0x50, 0x42, 0x45, 0x47, 0x49, 0x4E",
            options(nostack, preserves_flags, readonly)
        );
    }

    // ==========================================
    // CRITICAL SECURITY LOGIC ZONE (Virtual-Safe)
    // ==========================================
    
    // Prevent optimization from stripping this block out completely
    std::hint::black_box(current_hwid);
    
    // Run all environmental verification routines inside the virtualization layer
    SecurityValidator::enforce_anti_debug();
    SecurityValidator::enforce_vm_detection();

    println!("[SECURITY Engine] All runtime environment integrity tokens verified successfully.");

    // ==========================================

    unsafe {
        // Replaced character strings with raw numerical byte literals compatible with LLVM assembler syntax
        asm!(
            ".byte 0xEB, 0x08, 0x56, 0x4D, 0x50, 0x45, 0x4E, 0x44, 0x4F, 0x46",
            options(nostack, preserves_flags, readonly)
        );
    }
}

pub struct SecurityValidator;

impl SecurityValidator {
    pub fn new() -> Self { Self }
    
    /// Checks the standard OS Win32 API layer for basic debug attachment flags
    pub fn enforce_anti_debug() {
        #[cfg(target_os = "windows")]
        unsafe {
            if IsDebuggerPresent() != 0 {
                println!("[SECURITY_FAULT] Unauthorized debugger detected. Self-terminating.");
                std::process::exit(1);
            }
        }
    }

    /// Hardened hardware-level hypervisor validation using intrinsic x86/x64 CPUID registers
    pub fn enforce_vm_detection() {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // FIXED: Removed unsafe completely! Rust considers __cpuid memory-safe natively.
            let leaf_1 = __cpuid(1);

            // Bit 31 of ECX is the hypervisor present bit (set by virtual machines)
            if (leaf_1.ecx & (1 << 31)) != 0 {
                // Query hypervisor signature information string (Leaf 0x40000000)
                let signature_leaf = __cpuid(0x40000000);

                // Reconstruct the brand character sequence from EBX, ECX, and EDX registers safely
                let mut brand_bytes = Vec::new();
                brand_bytes.extend_from_slice(&signature_leaf.ebx.to_le_bytes());
                brand_bytes.extend_from_slice(&signature_leaf.ecx.to_le_bytes());
                brand_bytes.extend_from_slice(&signature_leaf.edx.to_le_bytes());
                
                let vm_signature = String::from_utf8_lossy(&brand_bytes).trim().to_string();

                println!(
                    "[SECURITY_FAULT] Virtualized architecture intercepted (Type: {}). Execution blocked.",
                    vm_signature
                );
                std::process::exit(1);
            }
        }
    }
}

// Global scope export hooks mapping to your main terminal loop structure
pub fn enforce_anti_debug() {
    SecurityValidator::enforce_anti_debug();
}

pub fn enforce_vm_detection() {
    SecurityValidator::enforce_vm_detection();
}