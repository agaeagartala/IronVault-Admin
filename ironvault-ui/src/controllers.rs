// =========================================================================
// IronVault Core UI Event Handlers & Controllers (controllers.rs)
// =========================================================================

use slint::ComponentHandle;
use ironvault_core::crypto;
use ironvault_core::database::postgres;

pub fn wire_ui_event_handlers(app: &slint::Weak<crate::AppWindow>, db_uri: String, machine_id: String) {
    let app_window = app.unwrap();
    
    // Bind hardware layout tokens and anchor workspace namespace properties on startup
    app_window.set_hardware_id(machine_id.clone().into());
    app_window.set_selected_schema("ironvault".into());

    // -------------------------------------------------------------
    // 1. STATEFUL LOGIN CONTROLLER & HARDWARE MACHINE BINDING
    // -------------------------------------------------------------
    let app_weak = app.clone();
    let db_uri_clone = db_uri.clone();
    let machine_id_clone = machine_id.clone();
    
    app_window.on_attempt_login(move |username, password| {
        let ui = app_weak.unwrap();
        let user_str = username.as_str().trim().to_string();
        let pass_str = password.as_str().trim().to_string();

        ui.set_error_message("".into()); 

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut login_allowed = false;
        let mut user_role = "operator".to_string();

        runtime.block_on(async {
            match postgres::establish_secure_connection(&db_uri_clone).await {
                Ok(client) => {
                    let calculated_hash = crypto::secure_hash_password(&pass_str, &user_str);
                    
                    // Match directly against your specific ironvault.users schema target
                    let query = "SELECT password, role FROM ironvault.users WHERE username = $1";
                    match client.query(query, &[&user_str]).await {
                        Ok(rows) if !rows.is_empty() => {
                            let db_hash: &str = rows[0].get(0);
                            let db_role: &str = rows[0].get(1);

                            if db_hash == calculated_hash {
                                login_allowed = true;
                                user_role = db_role.to_string();
                                
                                // Write to the system audit trails on successful entry
                                let log_query = "
                                    INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) 
                                    VALUES ($1, 'AUTH_SUCCESS', $2)";
                                let log_msg = format!("Authorized secure session token generated. Machine Fingerprint: {}", machine_id_clone);
                                let _ = client.execute(log_query, &[&user_str, &log_msg]).await;
                            } else {
                                // Audit Log for wrong password
                                let log_query = "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'AUTH_FAILURE', $2)";
                                let log_msg = format!("Rejected access credentials signature match. Machine ID: {}", machine_id_clone);
                                let _ = client.execute(log_query, &[&user_str, &log_msg]).await;
                            }
                        }
                        Ok(_) => {
                            ui.set_error_message("Identity payload profile not found inside ironvault workspace.".into());
                        }
                        Err(e) => eprintln!("[DB MALFUNCTION] Failed evaluating users namespace criteria: {}", e),
                    }
                }
                Err(e) => eprintln!("[NETWORK ERROR] Secure database socket pool unreached: {}", e),
            }
        });

        if login_allowed {
            ui.set_is_authenticated(true);
            ui.set_current_user(user_str.into());
            ui.set_current_role(user_role.into());
            ui.set_status_banner_text(format!("OPERATOR SESSION SIGNED ON SAFELY").into());
            ui.set_status_banner_color(slint::Color::from_rgb_u8(16, 185, 129));
        } else {
            ui.set_error_message("CRITICAL SECURITY EXCEPTION: Key authorization handshake verification failed.".into());
        }
    });

    // -------------------------------------------------------------
    // 2. ACCOUNT SYSTEM PROVISIONING REGISTRATION
    // -------------------------------------------------------------
    let app_weak = app.clone();
    let db_uri_clone = db_uri.clone();
    app_window.on_trigger_registration(move |username, password| {
        let ui = app_weak.unwrap();
        let user_str = username.as_str().trim().to_string();
        let pass_str = password.as_str().trim().to_string();

        if user_str.is_empty() || pass_str.is_empty() {
            ui.set_error_message("Cannot write empty parameters into configuration profiles.".into());
            return;
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut registered = false;

        runtime.block_on(async {
            if let Ok(client) = postgres::establish_secure_connection(&db_uri_clone).await {
                let password_hash = crypto::secure_hash_password(&pass_str, &user_str);
                
                let insert_query = "
                    INSERT INTO ironvault.users (username, password, role) 
                    VALUES ($1, $2, 'admin')";
                
                match client.execute(insert_query, &[&user_str, &password_hash]).await {
                    Ok(_) => {
                        registered = true;
                        let log_query = "INSERT INTO ironvault.system_audit_logs (operator_username, action_type, details) VALUES ($1, 'USER_REGISTERED', 'New admin identity profile appended to core.')";
                        let _ = client.execute(log_query, &[&user_str, &"Provisioned account."]).await;
                    }
                    Err(e) => eprintln!("[REGISTRATION BLOCK] Constraint protection conflict: {}", e),
                }
            }
        });

        if registered {
            ui.set_error_message("Registration committed cleanly to ironvault schema tables!".into());
        } else {
            ui.set_error_message("Identity registration refused: Constraint violation or duplicate profile error.".into());
        }
    });

    // -------------------------------------------------------------
    // 3. CRYPTOGRAPHIC SUPERVISOR DUAL-KEY SECURITY INTERLOCK
    // -------------------------------------------------------------
    let app_weak = app.clone();
    app_window.on_verify_supervisor_keys(move |op_key, sv_key| {
        let ui = app_weak.unwrap();
        let op_valid = crypto::verify_authority_signature(op_key.as_str().trim());
        let sv_valid = crypto::verify_authority_signature(sv_key.as_str().trim());

        if op_valid && sv_valid {
            ui.set_crypto_signature_status("✅ INTERLOCK SECURITY ENGAGED".into());
            ui.set_status_banner_text("DUAL-KEY CRYPTO VERIFICATION SIGNATURE MATCHED".into());
            ui.set_status_banner_color(slint::Color::from_rgb_u8(16, 185, 129));
        } else {
            ui.set_crypto_signature_status("❌ ACCESS SIGNATURE REFUSED".into());
            ui.set_status_banner_text("SECURITY EXCEPTION: COMPROMISED CERTIFICATE KEYS SUBMITTED".into());
            ui.set_status_banner_color(slint::Color::from_rgb_u8(239, 68, 68));
        }
    });

    // -------------------------------------------------------------
    // 4. CLEAN DISCONNECT & TERMINATION ROUTINE
    // -------------------------------------------------------------
    let app_weak = app.clone();
    app_window.on_trigger_logout(move || {
        let ui = app_weak.unwrap();
        ui.set_is_authenticated(false);
        ui.set_current_user("Unauthenticated Session".into());
        ui.set_current_role("guest".into());
        ui.set_status_banner_text("SESSION TOKEN RECOVERED AND PURGED".into());
        ui.set_status_banner_color(slint::Color::from_rgb_u8(56, 189, 248));
        println!("[SECURITY] Administrative session tokens cleared from active application runtime memory cache.");
    });
}