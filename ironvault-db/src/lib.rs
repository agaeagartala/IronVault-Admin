//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

pub fn verify_login(user: &str, pass: &str) -> Result<ironvault_core::auth::UserSession, String> {
    if user == "admin" && pass == "admin123" {
        Ok(ironvault_core::auth::UserSession {
            username: "John Doe".to_string(),
            role: ironvault_core::auth::Role::SuperAdmin,
            last_login: "Today, 17:02 IST".to_string(),
        })
    } else {
        Err("Invalid Credentials".to_string())
    }
}