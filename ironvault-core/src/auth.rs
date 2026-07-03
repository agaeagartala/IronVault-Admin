//! Role-Based Access Control (RBAC)
//!
//! Implements four-tier permission hierarchy:
//! - Super Admin: Full system control
//! - Admin: Manage users and configurations
//! - Operator: Execute approved actions
//! - Viewer: Read-only access

#[derive(Debug, Clone, PartialEq)]
pub enum Role { SuperAdmin, Admin, Operator, Viewer }

pub struct UserSession {
    pub username: String,
    pub role: Role,
    pub last_login: String,
}