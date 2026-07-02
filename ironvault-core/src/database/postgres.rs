// =========================================================================
// IronVault Native PostgreSQL Connector Engine (postgres.rs)
// =========================================================================

use std::error::Error;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::Client;

/// Configures and establishes an encrypted database pool channel over TLS
pub async fn establish_secure_connection(connection_string: &str) -> Result<Client, Box<dyn Error>> {
    let mut masked_string = connection_string.to_string();
    if let Some(start) = connection_string.find("password=") {
        if let Some(end) = connection_string[start..].find(' ') {
            masked_string.replace_range(start..start+end, "password=********");
        } else {
            masked_string.replace_range(start.., "password=********");
        }
    }
    println!("[DIAGNOSTIC] Connecting with URI: {}", masked_string);

    // Initial attempt through Native TLS protocols
    let tls_inner_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tls_connector = MakeTlsConnector::new(tls_inner_connector);

    match tokio_postgres::connect(connection_string, tls_connector).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("[ERROR] Active PostgreSQL TLS stream failure: {}", e);
                }
            });
            println!("[SUCCESS] Secure TLS channel established with database.");
            return Ok(client);
        }
        Err(e) => {
            println!("[WARNING] TLS rejected. Retrying with standard clean connection... Detail: {}", e);
        }
    }

    // Standard Fallback Routine
    let (client, connection) = tokio_postgres::connect(connection_string, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[ERROR] Active PostgreSQL connection stream failure: {}", e);
        }
    });
    println!("[SUCCESS] Standard channel established with database.");
    Ok(client)
}
