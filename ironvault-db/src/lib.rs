//! IronVault Database Access Layer
//!
//! Provides ORM and database operations for PostgreSQL and Oracle

use sqlx::{PgPool, postgres::PgPoolOptions, Row};

#[derive(Clone, Debug)]
pub struct DbUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
}

#[derive(Clone, Debug)]
pub struct ActiveUser {
    pub username: String,
    pub role: String,
    pub last_login: String,
}

#[derive(Clone)]
pub struct DbClient {
    pool: PgPool,
}

impl DbClient {
    pub async fn connect_with_credentials(
        host: &str,
        port: u16,
        db_name: &str, // FIXED: Removed the underscore so we can use this variable!
        user: &str,
        pass: &str,
    ) -> Result<Self, String> {
        // FIXED: Dynamically inject the db_name (AsstPro) instead of hardcoding "postgres"
        let database_url = format!("postgres://{}:{}@{}:{}/{}", user, pass, host, port, db_name);
        
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .map_err(|e| format!("Database cluster handshake failed: {}", e))?;
            
        Ok(Self { pool })
    }

    pub async fn authenticate_user(&self, username: &str, _pass: &str, hwid: &str) -> Result<DbUser, String> {
        let row = sqlx::query(
            "SELECT username, role, COALESCE(last_login_at::text, 'NEVER') as last_login FROM ironvault.users WHERE username = $1 AND status = 'ACTIVE' AND hardware_fingerprint = $2"
        )
        .bind(username)
        .bind(hwid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        if let Some(r) = row {
            sqlx::query("UPDATE ironvault.users SET last_login_at = NOW() WHERE username = $1")
                .bind(username)
                .execute(&self.pool)
                .await
                .ok();

            Ok(DbUser {
                username: r.get("username"),
                role: r.get("role"),
                last_login: r.get("last_login"),
            })
        } else {
            Err("Invalid credentials, HWID mismatch, or account is not ACTIVE.".to_string())
        }
    }

    pub async fn register_user(&self, username: &str, hashed_pass: &str, hwid: &str) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO ironvault.users (username, password, role, status, hardware_fingerprint) VALUES ($1, $2, 'Operator', 'PENDING', $3) ON CONFLICT DO NOTHING"
        )
        .bind(username)
        .bind(hashed_pass)
        .bind(hwid)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Registration record reject: {}", e))?;
        Ok(())
    }

    pub async fn fetch_next_pending_user(&self) -> Result<Option<String>, String> {
        let row = sqlx::query("SELECT username FROM ironvault.users WHERE status = 'PENDING' LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
            
        Ok(row.map(|r| r.get("username")))
    }

    pub async fn approve_user(&self, _admin: &str, target_user: &str, assigned_role: &str) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET status = 'ACTIVE', role = $1 WHERE username = $2")
            .bind(assigned_role)
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn deny_user(&self, _admin: &str, target_user: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1 AND status = 'PENDING'")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_active_users(&self) -> Result<Vec<ActiveUser>, String> {
        let rows = sqlx::query(
            "SELECT username, role, COALESCE(last_login_at::text, 'NEVER') as last_login FROM ironvault.users WHERE status = 'ACTIVE' ORDER BY role, username"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Failed to fetch operators: {}", e))?;

        let users = rows.into_iter().map(|r| ActiveUser {
            username: r.get("username"),
            role: r.get("role"),
            last_login: r.get("last_login"),
        }).collect();

        Ok(users)
    }

    pub async fn update_user_role(&self, _admin_name: &str, target_user: &str, new_role: &str) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET role = $1 WHERE username = $2 AND status = 'ACTIVE'")
            .bind(new_role)
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to update role state: {}", e))?;
        Ok(())
    }

    pub async fn ban_user(&self, _admin_name: &str, target_user: &str) -> Result<(), String> {
        sqlx::query("DELETE FROM ironvault.users WHERE username = $1")
            .bind(target_user)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to execute revocation purge: {}", e))?;
        Ok(())
    }
}