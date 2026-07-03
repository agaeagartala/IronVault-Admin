//! IronVault Admin UI - Bootstrapper & Main Thread
//!
//! Initializes the Slint UI framework and establishes connections
//! to the core security and database layers

// Bypass Slint macro IDE bug
mod ui {
    include!(concat!(env!("OUT_DIR"), "/ui/main.rs"));
}
use ui::AppWindow;
use slint::ComponentHandle;

fn main() -> Result<(), slint::PlatformError> {
    println!("[BOOT] Engaging IronVault Core Security...");
    
    // 1. Enforce Hardware Anti-Debug Protection
    ironvault_core::security::enforce_anti_debug();
    
    // 2. Generate Irreversible Hardware ID
    let hwid = ironvault_core::licensing::generate_hwid();
    println!("[SECURITY] Computed System HWID: {}", hwid);

    // 3. Launch UI
    let app = AppWindow::new()?;
    
    // Inject HWID to UI
    app.set_hwid_string(format!("HWID: {}", hwid).into());
    
    // 4. Handle Secure Login Requests
    let app_weak = app.as_weak();
    app.on_request_authentication(move |username, password| {
        let ui = app_weak.unwrap();
        
        match ironvault_db::verify_login(&username, &password) {
            Ok(session) => {
                ui.set_login_error("".into());
                ui.set_current_user_name(session.username.into());
                ui.set_current_user_role("Super Admin".into());
                ui.set_last_login(session.last_login.into());
                ui.set_is_logged_in(true);
                println!("[AUTH] System Unlocked for {}", session.username);
            }
            Err(e) => {
                ui.set_login_error(e.into());
            }
        }
    });

    app.run()
}