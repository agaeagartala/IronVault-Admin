use crate::AppWindow;
use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::rc::Rc;

pub fn setup_event_handlers(app: &AppWindow) {
    let app_weak = app.as_weak();

    // 1. Hook Up the Grid Update/Modification Callback
    app.on_update_record_commit(move |index, new_title, new_status| {
        let ui = app_weak.unwrap();
        
        // Extract the existing row data model array from Slint state context
        let current_model = ui.get_table_data();
        
        // Build a fresh vector to compute modified changes
        let mut updated_vector = Vec::new();
        for i in 0..current_model.row_count() {
            if let Some(mut record) = current_model.row_data(i) {
                // If this is the row the operator clicked on, inject the modifications
                if i == index as usize {
                    record.title = new_title.clone();
                    record.status = new_status.clone();
                }
                updated_vector.push(record);
            }
        }

        // Wrap it back into a Slint compatible shared vector model pointer structure
        let new_model = Rc::new(VecModel::from(updated_vector));
        
        // Re-inject the data right back into the UI. The grid updates on screen immediately!
        ui.set_table_data(new_model.into());
        
        // Unselect the row panel and push a success message down to the console status bar
        ui.set_selected_row_index(-1);
        ui.set_status_text("SUCCESS: Modifications committed to memory model.".into());
    });

    // 2. Legacy Empty Callback Bindings to maintain module integrity
    app.on_execute_11g_action(|_, _| {});
    app.on_execute_12c_action(|_, _| {});
}