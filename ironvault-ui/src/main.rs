//! IronVault Admin UI - Bootstrapper & Main Thread
//!
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

// Reverted back to the native slint macro to fix the rust-analyzer macro-error completely

slint::include_modules!();

use slint::ComponentHandle;
use ironvault_core::audit::AuditLogger;
use ironvault_core::auth::User;

fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    // 1. Enforce Hardware Anti-Debug Protection
    ironvault_core::security::enforce_anti_debug();
    
    // 2. Generate Irreversible Hardware ID
    let hwid = ironvault_core::licensing::generate_hwid();
    println!("[SECURITY] Computed System HWID: {}", hwid);

    // 3. Initialize Immutable Secure Audit Ledger Engine
    let audit_logger = AuditLogger::new("ironvault.audit.log");

    // 4. Launch UI
    let app = AppWindow::new()?;
    
    // Inject HWID to UI
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    // 5. Handle Secure Login Requests with Audit Ledger Binding
    let app_weak = app.as_weak();
    app.on_request_authentication(move |username, password| {
        let ui = app_weak.unwrap();
        
        match ironvault_db::verify_login(&username, &password) {
            Ok(session) => {
                ui.set_login_error("".into());
                
                // Construct a true core User struct model for logging serialization bounds
                let runtime_user = User {
                    id: "IV-USR-001".to_string(),
                    username: session.username.clone(),
                    role: ironvault_core::auth::Role::SuperAdmin,
                    last_login: session.last_login.clone(),
                };

                // Commit explicit CRITICAL confirmation event straight to the immutable file ledger
                if let Err(err) = audit_logger.log_action(
                    &runtime_user, 
                    "OPERATOR_AUTHENTICATION_SUCCESS // WORKSPACE SECURE ESCROW ACCESS GRANTED", 
                    "CRITICAL"
                ) {
                    eprintln!("[LEDFER_FAULT] Failed to write secure log line: {}", err);
                }

                ui.set_current_user_name(session.username.clone().into());
                ui.set_current_user_role("Super Admin".into());
                ui.set_last_login(session.last_login.into());
                ui.set_is_logged_in(true);
                
                println!("[AUTH] System Unlocked for {}", session.username);
            }
            Err(e) => {
                ui.set_login_error(e.into());
                
                // Construct a fallback guest entry trace to ledger anonymous breach attempts
                let failed_user = User {
                    id: "IV-USR-ANON".to_string(),
                    username: username.to_string(),
                    role: ironvault_core::auth::Role::Viewer,
                    last_login: "ACCESS_DENIED".to_string(),
                };

                // Record warning trace to disk regarding rejected credentials
                if let Err(err) = audit_logger.log_action(
                    &failed_user, 
                    &format!("REJECTED_AUTHENTICATION_ATTEMPT // UNREGISTERED OPERATOR ID: {}", username), 
                    "WARNING"
                ) {
                    eprintln!("[LEDGER_FAULT] Failed to write breach attempt log line: {}", err);
                }
            }
        }
    });

    app.run()
}