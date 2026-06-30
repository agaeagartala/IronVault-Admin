// =========================================================================
// IronVault UI Core Application Launcher (main.rs)
// Connects declarative Slint interface components to Rust runtime services.
// =========================================================================

slint::include_modules!();

#[tokio::main]
async fn main() -> Result<(), slint::PlatformError> {
    // Instantiate UI Window Object
    let app = AppWindow::new()?;

    // Register signature verification callback
    app.on_sign_authority_key(|raw_key| {
        println!("[SECURITY] Verifying cryptographic entry signature locally...");
        // Invoke local cryptographic library logic
        let success = ironvault_core::crypto::verify_authority_signature(&raw_key);
        if success {
            println!("[AUDIT] Cryptographic signature validation succeeded. Action committed.");
        } else {
            eprintln!("[SECURITY WARNING] Invalid private key structure submitted.");
        }
        success
    });

    // Register backend operation callback
    app.on_request_action(|action, target| {
        println!("[ACTION-REQUEST] Executing: {} on Target Schema: {}", action, target);
        // Safely routes to our background database modules based on requested activity
        if action.contains("Downgrade") {
            match ironvault_core::database::oracle::execute_downgrade_export("SCOTT") {
                Ok(log) => println!("[ORACLE PIPELINE SUCCESS] {}", log),
                Err(err) => eprintln!("[ORACLE PIPELINE FAILURE] {}", err),
            }
        }
    });

    // Run Desktop Event Loop
    app.run()
}