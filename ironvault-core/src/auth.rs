//! Role-Based Access Control (RBAC)
//!
//! Implements four-tier permission hierarchy:
//! - Super Admin: Full system control
//! - Admin: Manage users and configurations
//! - Operator: Execute approved actions
//! - Viewer: Read-only access

use crate::sdk_vmp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    SuperAdmin,
    Admin,
    Operator,
    Viewer,
}

pub enum AuthDecision {
    GrantFullSession,
    RequireForcedPasswordReset,
    Deny,
}

pub fn classify_auth_outcome(
    normal_auth_result: &Result<(), ()>,
    temp_token_result: &Result<(), ()>,
) -> AuthDecision {
    sdk_vmp::vmp_begin_ultra("ClassifyAuthOutcome");

    let decision = if normal_auth_result.is_ok() {
        AuthDecision::GrantFullSession
    } else if temp_token_result.is_ok() {
        AuthDecision::RequireForcedPasswordReset
    } else {
        AuthDecision::Deny
    };

    sdk_vmp::vmp_end();
    decision
}

impl From<String> for Role {
    fn from(s: String) -> Self {
        match s.as_str() {
            "SuperAdmin" => Role::SuperAdmin,
            "Admin" => Role::Admin,
            "Operator" => Role::Operator,
            _ => Role::Viewer,
        }
    }
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::SuperAdmin => "SuperAdmin".to_string(),
            Role::Admin => "Admin".to_string(),
            Role::Operator => "Operator".to_string(),
            Role::Viewer => "Viewer".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub last_login: String,
}

// Re-added to satisfy ironvault-core/src/lib.rs exports perfectly
pub struct AuthManager;

impl AuthManager {
    pub fn new() -> Self {
        Self
    }
}

pub struct UserSession {
    pub username: String,
    pub role: Role,
    pub last_login: String,
}
