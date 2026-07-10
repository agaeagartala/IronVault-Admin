//! PostgreSQL Core User Profile Storage Manager

use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct DbClient {
    pool: PgPool,
}

impl DbClient {
    pub async fn connect_with_credentials(
        host: &str,
        port: u16,
        db_name: &str,
        user: &str,
        pass: &str,
    ) -> Result<Self, String> {
        let connection_string =
            format!("postgres://{}:{}@{}:{}/{}", user, pass, host, port, db_name);
        let pool = PgPool::connect(&connection_string)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { pool })
    }

    pub fn get_pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn authenticate_user(
        &self,
        username: &str,
        password_token: &str,
        _hwid: &str,
    ) -> Result<ironvault_core::auth::User, String> {
        // Safe runtime query sequence completely bypassed from compile-time macro constraints
        let row = sqlx::query("SELECT username, role, last_login FROM ironvault.users WHERE username = $1 AND secret_token = $2 AND status = 'ACTIVE'")
            .bind(username)
            .bind(password_token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(r) = row {
            let u: String = r.try_get("username").unwrap_or_default();
            let role_str: String = r.try_get("role").unwrap_or_default();
            let last: String = r.try_get("last_login").unwrap_or_default();

            Ok(ironvault_core::auth::User {
                id: Default::default(),
                username: u,
                role: role_str.into(),
                last_login: last,
            })
        } else {
            Err("Authentication Failed: Credentials rejected by gatekeeper node.".to_string())
        }
    }

    pub async fn update_user_lease(
        &self,
        username: &str,
        role: &str,
        days: i32,
    ) -> Result<(), String> {
        sqlx::query("UPDATE ironvault.users SET role = $1, expires_at = NOW() + make_interval(days => $2) WHERE username = $3")
            .bind(role)
            .bind(days)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
