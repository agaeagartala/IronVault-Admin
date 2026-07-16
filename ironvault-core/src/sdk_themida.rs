//! Themida / SecureEngine Native SDK Bindings
//! Enforces memory-level wrapping and execution blocks for UI/Database routes.

#[link(name = "SecureEngineSDK64")]
extern "C" {
    fn VMStart();
    fn VMEnd();
    fn EncodeMacroStart();
    fn EncodeMacroEnd();
}

pub fn themida_vm_start() {
    unsafe {
        VMStart();
    }
}

pub fn themida_vm_end() {
    unsafe {
        VMEnd();
    }
}

pub fn themida_encode_start() {
    unsafe {
        EncodeMacroStart();
    }
}

pub fn themida_encode_end() {
    unsafe {
        EncodeMacroEnd();
    }
}
