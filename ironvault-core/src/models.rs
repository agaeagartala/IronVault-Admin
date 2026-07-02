// =========================================================================
// IronVault Core Domain Models & Roles (models.rs)
// =========================================================================

use serde::{Serialize, Deserialize};

/// Stateful roles matching enterprise verification clearance gates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperatorRole {
    SuperAdmin,
    Operator,
    Auditor,
}

impl OperatorRole {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "admin" | "superadmin" => OperatorRole::SuperAdmin,
            "operator" => OperatorRole::Operator,
            _ => OperatorRole::Auditor,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            OperatorRole::SuperAdmin => "superadmin".to_string(),
            OperatorRole::Operator => "operator".to_string(),
            OperatorRole::Auditor => "auditor".to_string(),
        }
    }
}

/// Active secure system state structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub token: String,
    pub username: String,
    pub role: OperatorRole,
    pub hardware_binding: String,
    pub session_start: u64,
}

/// Domain schema representing authorized admins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserRecord {
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub machine_binding: String, // Dynamic fingerprint lock
}