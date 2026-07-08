//! Oracle Multi-Pool Matrix Controller
//!
//! Manages separate connection pools for completely distinct schemas
//! and handles individual workloads per node without cross-contamination.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OracleTarget {
    Gpffp,
    Vlcs,
    Agtall,
    Agdak,
    SaiAgartala,
    Pendak,
    Penindex,
}

pub struct OracleConnection {
    pool_gpffp: oracle::pool::Pool,
    pool_vlcs: oracle::pool::Pool,
    pool_agtall: oracle::pool::Pool,
    pool_agdak: oracle::pool::Pool,
    pool_sai_agartala: oracle::pool::Pool,
    pool_pendak: oracle::pool::Pool,
    pool_penindex: oracle::pool::Pool,
}

impl OracleConnection {
    /// Initialize all 7 discrete schema connection pools across both network clusters
    pub fn new() -> Result<Self, String> {
        // --- CLUSTER 1 (192.168.100.247 / SID: db11g) ---
        let tns_100 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.100.247)(PORT=1521))(CONNECT_DATA=(SID=db11g)))";
        
        let pool_gpffp = oracle::pool::PoolBuilder::new("gpffp", "gpffp", tns_100)
            .build().map_err(|e| format!("gpffp node link failure: {}", e))?;
            
        let pool_vlcs = oracle::pool::PoolBuilder::new("vlcs", "vlcs", tns_100)
            .build().map_err(|e| format!("vlcs node link failure: {}", e))?;
            
        let pool_agtall = oracle::pool::PoolBuilder::new("agtall", "agtall", tns_100)
            .build().map_err(|e| format!("agtall node link failure: {}", e))?;
            
        let pool_agdak = oracle::pool::PoolBuilder::new("agdak", "agdak", tns_100)
            .build().map_err(|e| format!("agdak node link failure: {}", e))?;

        // --- CLUSTER 2 (192.168.0.140 / SID: orcl) ---
        let tns_0 = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.0.140)(PORT=1521))(CONNECT_DATA=(SID=orcl)))";
        
        let pool_sai_agartala = oracle::pool::PoolBuilder::new("sai_agartala", "sai_agartala", tns_0)
            .build().map_err(|e| format!("sai_agartala node link failure: {}", e))?;
            
        let pool_pendak = oracle::pool::PoolBuilder::new("pendak", "pendak", tns_0)
            .build().map_err(|e| format!("pendak node link failure: {}", e))?;
            
        let pool_penindex = oracle::pool::PoolBuilder::new("penindex", "penindex", tns_0)
            .build().map_err(|e| format!("penindex node link failure: {}", e))?;

        Ok(Self {
            pool_gpffp,
            pool_vlcs,
            pool_agtall,
            pool_agdak,
            pool_sai_agartala,
            pool_pendak,
            pool_penindex,
        })
    }

    /// Internal helper to lease a connection directly from the requested target pool
    fn get_connection(&self, target: OracleTarget) -> Result<oracle::Connection, String> {
        match target {
            OracleTarget::Gpffp => self.pool_gpffp.get().map_err(|e| e.to_string()),
            OracleTarget::Vlcs => self.pool_vlcs.get().map_err(|e| e.to_string()),
            OracleTarget::Agtall => self.pool_agtall.get().map_err(|e| e.to_string()),
            OracleTarget::Agdak => self.pool_agdak.get().map_err(|e| e.to_string()),
            OracleTarget::SaiAgartala => self.pool_sai_agartala.get().map_err(|e| e.to_string()),
            OracleTarget::Pendak => self.pool_pendak.get().map_err(|e| e.to_string()),
            OracleTarget::Penindex => self.pool_penindex.get().map_err(|e| e.to_string()),
        }
    }

    /// WORKLOAD: GPFFP Specific Task - Delete Full Case
    pub async fn gpffp_delete_full_case(&self, regd_no: &str, series_id: &str, account_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let s_id = series_id.to_string();
        let a_no = account_no.to_string();
        
        // Safely acquires the connection directly from the authentic GPFFP pool context
        let conn = self.get_connection(OracleTarget::Gpffp)?;

        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_INWARD_DIARY WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            // Cross-schema task update targeting VLCS (requires GPFFP to have grants on VLCS.GP_ACCOUNTS)
            conn.execute("UPDATE VLCS.GP_ACCOUNTS SET ACCOUNT_CLOSED_TAG = NULL WHERE SERIES_ID = :1 AND ACCOUNT_NO = :2", &[&s_id, &a_no])
                .map_err(|e| e.to_string())?;
            
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// WORKLOAD: GPFFP Specific Task - Delete From Application
    pub async fn gpffp_delete_from_application(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;

        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_APPLICATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// WORKLOAD: GPFFP Specific Task - Delete From Pre-Calculation
    pub async fn gpffp_delete_from_pre_calculation(&self, regd_no: &str) -> Result<(), String> {
        let r_no = regd_no.to_string();
        let conn = self.get_connection(OracleTarget::Gpffp)?;

        tokio::task::spawn_blocking(move || {
            conn.execute("DELETE FROM FP_MAIN WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_SUBSCRIPTION_DETAILS WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_MISSING_CREDIT WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM FP_ACCOUNT_CALCULATION WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            conn.execute("UPDATE FP_APPLICATION SET CALCULATION_DATE = NULL WHERE REGD_NO = :1", &[&r_no]).map_err(|e| e.to_string())?;
            
            conn.commit().map_err(|e| format!("GPFFP Commit failure: {}", e))?;
            Ok(())
        })
        .await
        .unwrap()
    }

    /// Real-time health validation across all cluster endpoints
    pub async fn health_check(&self) -> Result<(), String> {
        // Check one pool from each server to ensure network routing is alive
        for target in &[OracleTarget::Gpffp, OracleTarget::SaiAgartala] {
            let conn = self.get_connection(*target)?;
            let row = conn.query_row("SELECT 1 FROM DUAL", &[]).map_err(|e| e.to_string())?;
            let _: i32 = row.get(0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}