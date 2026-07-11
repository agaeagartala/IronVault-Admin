//! IronVault Database Access Layer
//! Provides ORM and database operations for PostgreSQL and Oracle

pub mod gpf;
pub mod oracle;
pub mod pendak;
pub mod postgres;
pub mod sai_agartala;
pub mod vlcs;

// Clean re-exports from child modules
pub use oracle::OracleConnection;
pub use postgres::{ActiveUser, DbClient, DbUser};
pub use sai_agartala::{PensionDetailsRecord, PensionStatusRecord};
