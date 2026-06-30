use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Auditor,
    Operator,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: u64,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: u64,
    pub description: String,
    pub amount: f64,
}
