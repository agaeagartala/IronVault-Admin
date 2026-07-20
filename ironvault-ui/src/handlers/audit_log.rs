use crate::context::SharedContext;
use crate::{AppWindow, AuditLogUiData};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;

pub fn register(app: &AppWindow, ctx: SharedContext) {
    let app_weak = app.as_weak();
    app.on_trigger_log_stream_reload(move || {
        let ui_weak = app_weak.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match ctx.db.fetch_recent_audit_logs(40).await {
                Ok(raw_records) => {
                    let mapped: Vec<AuditLogUiData> = raw_records
                        .into_iter()
                        .map(|item| AuditLogUiData {
                            timestamp: item.timestamp.into(),
                            operator_id: item.operator_id.into(),
                            operation_action: item.operation_action.into(),
                            level: item.level.into(),
                        })
                        .collect();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_dashboard_audit_stream(ModelRc::from(Rc::new(VecModel::from(
                                mapped,
                            ))));
                        }
                    })
                    .unwrap();
                }
                Err(e) => log::error!(
                    "[AUDIT] Failed to load audit log stream from database: {}",
                    e
                ),
            }
        });
    });
}
