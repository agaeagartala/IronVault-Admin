// =========================================================================
// IronVault Machine-Binding & Session Auth Controller (auth.rs)
// =========================================================================

use ironvault_core::models::{ActiveSession, OperatorRole};
use std::sync::Mutex;

static ACTIVE_SESSION: Mutex<Option<ActiveSession>> = Mutex::new(None);

/// Initiates a system session token with hardware locks paired to the runtime operator
pub fn establish_active_session(username: &str, role_str: &str, machine_id: &str) {
    let mut session = ACTIVE_SESSION.lock().unwrap();
    let token = format!("IV-TOKEN-{}-{}", username.to_uppercase(), machine_id[0..6].to_uppercase());
    
    *session = Some(ActiveSession {
        token,
        username: username.to_string(),
        role: OperatorRole::from_str(role_str),
        hardware_binding: machine_id.to_string(),
        session_start: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
}

/// Tears down active session properties during safe system exits
pub fn invalidate_session() {
    let mut session = ACTIVE_SESSION.lock().unwrap();
    *session = None;
}

/// Helper returning the signature status of the logged-in machine profile
pub fn get_session_operator_profile() -> Option<(String, String)> {
    let session = ACTIVE_SESSION.lock().unwrap();
    session.as_ref().map(|s| (s.username.clone(), s.role.to_string()))
}