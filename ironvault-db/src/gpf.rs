//! GPF Final Payment Subsystem Business Logics Module

use crate::oracle::{OracleConnection, OracleTarget};

#[derive(Debug, Clone)]
pub struct GpfCaseRecord {
    pub regd_no: String,
    pub acc_holder_name: String,
    pub series_id: String,
    pub account_no: String,
    pub closing_balance: f64,
    pub current_status: String,
}

impl OracleConnection {
    pub async fn gpffp_find_case_profile(&self, regd_no: &str) -> Result<Option<GpfCaseRecord>, String> {
        let r_no = regd_no.trim().to_string();
        if r_no.is_empty() { return Ok(None); }
        let conn = self.get_connection(OracleTarget::Gpffp)?;

        tokio::task::spawn_blocking(move || {
            let query = "SELECT REGD_NO, ACC_HOLDER_NAME, SERIES_ID, ACCOUNT_NO, STATUS FROM FP_APPLICATION WHERE REGD_NO = :regd AND ROWNUM <= 1";
            let mut stmt = conn.statement(query).build().map_err(|e| e.to_string())?;
            let rows = stmt.query_named(&[("regd", &r_no.as_str())]).map_err(|e| e.to_string())?;
            for row_result in rows {
                let row = row_result.map_err(|e| e.to_string())?;
                return Ok(Some(GpfCaseRecord {
                    regd_no: row.get(0).map_err(|e| e.to_string())?,
                    acc_holder_name: row.get(1).map_err(|e| e.to_string())?,
                    series_id: row.get(2).map_err(|e| e.to_string())?,
                    account_no: row.get(3).map_err(|e| e.to_string())?,
                    closing_balance: 0.0, 
                    current_status: row.get(4).map_err(|e| e.to_string())?,
                }));
            }
            Ok(None)
        }).await.unwrap()
    }

    pub async fn gpffp_delete_full_case(&self, regd_no: &str, _s_id: &str, _a_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        if r_no.len() < 5 {
            return Err("Security Mismatch: REGD_NO length is invalid for token slicing extraction format.".to_string());
        }

        let extracted_series = r_no[2..4].to_string();
        let extracted_account = r_no[4..].to_string();

        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;

            let optional_tables = ["FP_INWARD_DAIRY", "FP_INWARD_DIARY", "FP_MAIN", "FP_SUBSCRIPTION_DETAILS", "FP_MISSING_CREDIT", "FP_ACCOUNT_CALCULATION"];
            for table in optional_tables.iter() {
                let query = format!("DELETE FROM {} WHERE REGD_NO = :1", table);
                let _ = conn.execute(&query, &[&r_no]); 
            }

            conn.execute("UPDATE VLCS.GP_ACCOUNTS SET ACCOUNT_CLOSED_TAG = NULL WHERE SERIES_ID = :1 AND ACCOUNT_NO = :2", &[&extracted_series, &extracted_account]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| e.to_string())?;
            Ok(())
        }).await.unwrap()
    }

    pub async fn gpffp_delete_from_application(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            for table in &["FP_SUBSCRIPTION_DETAILS", "FP_MISSING_CREDIT", "FP_ACCOUNT_CALCULATION"] {
                let _ = conn.execute(&format!("DELETE FROM {} WHERE REGD_NO = :1", table), &[&r_no]);
            }
            conn.commit().map_err(|e| e.to_string())?;
            Ok(())
        }).await.unwrap()
    }

    pub async fn gpffp_delete_from_pre_calculation(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;
        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            for table in &["FP_SUBSCRIPTION_DETAILS", "FP_MISSING_CREDIT", "FP_ACCOUNT_CALCULATION"] {
                let _ = conn.execute(&format!("DELETE FROM {} WHERE REGD_NO = :1", table), &[&r_no]);
            }
            conn.execute("UPDATE FP_APPLICATION SET CALCULATION_DATE = NULL WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.commit().map_err(|e| e.to_string())?;
            Ok(())
        }).await.unwrap()
    }
}