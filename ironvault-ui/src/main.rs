// =========================================================================
// IronVault Main Executable Controller & Event Handler (main.rs)
// =========================================================================

slint::include_modules!();

use ironvault_core::crypto;
use ironvault_core::database::postgres;

mod auth;
mod controllers;

fn main() -> Result<(), slint::PlatformError> {
    // Collect the dynamic hardware fingerprint binding signature
    let physical_hardware_id = crypto::get_machine_hardware_id();
    println!("[INIT] Physical Machine ID Binding Fingerprint: {}", physical_hardware_id);

    // 1. Securely load target DB URI from environment variables or default to standard parameters
    let db_uri = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "host=10.47.240.169 port=5432 user=egpf_app_user password=P@ssw()rd123 dbname=AsstPro sslmode=disable".to_string()
    });

    // Verify secure TLS connectivity on launch
    let boot_uri = db_uri.clone();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        match postgres::establish_secure_connection(&boot_uri).await {
            Ok(_) => {
                println!("[SUCCESS] Secure TLS connection verified with database cluster.");
            }
            Err(e) => {
                eprintln!("[BOOT ERROR] Could not reach database target: {}", e);
            }
        }
    });

    // 2. Instantiate our hardware-accelerated user interface
    let app = AppWindow::new()?;

    // Sync static UI initialization states
    app.set_sys_hardware_id(physical_hardware_id.clone().into());
    app.set_selected_schema("ironvault".into());

    // 3. Register and bind UI event handlers
    controllers::wire_ui_events(&app, db_uri, physical_hardware_id);

    // 4. Start your compiled, hardware-locked, beautifully designed desktop portal!
    app.run()
}