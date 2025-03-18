use crate::r#struct::{
    BoolResult, CertRecord, CertificateResponse, Certinfo, Config, DEFAULT_MYSQL_PORT,
    DEFAULT_MYSQL_TABLE, DEFAULT_POSTGRES_PORT, DEFAULT_POSTGRES_TABLE,
};
use async_trait::async_trait;
use chrono::{Datelike, NaiveDateTime, Timelike};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_types;
use diesel::{MysqlConnection, PgConnection};
use log::{debug, info, warn};
use ocsp::common::asn1::GeneralizedTime;
use ocsp::response::{CertStatus as OcspCertStatus, CertStatusCode, CrlReason, RevokedInfo};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

type MysqlPool = Pool<ConnectionManager<MysqlConnection>>;
type PgPool = Pool<ConnectionManager<PgConnection>>;

pub enum DatabaseType {
    MySQL,
    PostgreSQL,
}

impl DatabaseType {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" => DatabaseType::PostgreSQL,
            _ => DatabaseType::MySQL,
        }
    }

    #[allow(dead_code)]
    fn default_table_name(&self) -> &'static str {
        match self {
            DatabaseType::MySQL => DEFAULT_MYSQL_TABLE,
            DatabaseType::PostgreSQL => DEFAULT_POSTGRES_TABLE,
        }
    }
}

#[async_trait]
pub trait Database: Send + Sync {
    async fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>>;

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>>;

    // New API-related methods
    async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

    async fn revoke_certificate(
        &self,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    async fn get_certificate_status(
        &self,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>>;

    async fn list_certificates(
        &self,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>>;
}

pub struct DieselMysqlDatabase {
    config: Arc<Config>,
    pool: MysqlPool,
    table_name: String,
}

impl DieselMysqlDatabase {
    pub fn new(config: Arc<Config>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let database_url = match &config.dbip {
            Some(host) => format!(
                "mysql://{}:{}@{}:{}/{}",
                config.dbuser,
                config.dbpassword,
                host,
                config.dbport.unwrap_or(DEFAULT_MYSQL_PORT),
                config.dbname
            ),
            None => format!(
                "mysql://{}:{}@localhost/{}",
                config.dbuser, config.dbpassword, config.dbname
            ),
        };

        let manager = ConnectionManager::<MysqlConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(15)
            .connection_timeout(Duration::from_secs(config.time as u64))
            .build(manager)?;

        let table_name = config
            .table_name
            .clone()
            .unwrap_or_else(|| DEFAULT_MYSQL_TABLE.to_string());

        Ok(Self {
            config,
            pool,
            table_name,
        })
    }

    fn get_connection(
        &self,
    ) -> Result<
        diesel::r2d2::PooledConnection<ConnectionManager<MysqlConnection>>,
        Box<dyn Error + Send + Sync>,
    > {
        Ok(self.pool.get()?)
    }
}

#[async_trait]
impl Database for DieselMysqlDatabase {
    async fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = certnum.to_string();
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Using text SQL query with explicit column names and types
            let query = format!(
                "SELECT cert_num, revocation_time, revocation_reason, status FROM {} WHERE cert_num = ?",
                table_name
            );

            let results = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<CertRecord>(&mut conn)?;

            if results.is_empty() {
                warn!("Entry not found for cert {}", cert_num);
                if !revoked {
                    Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
                } else {
                    Ok(OcspCertStatus::new(
                        CertStatusCode::Revoked,
                        Some(RevokedInfo::new(
                            GeneralizedTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
                            Some(CrlReason::OcspRevokeCertHold),
                        )),
                    ))
                }
            } else {
                let record = &results[0];
                debug!("Entry found for cert {}, status {}", cert_num, record.status);

                if record.status == "Revoked" {
                    let time = GeneralizedTime::now();

                    let time = if let Some(rt) = record.revocation_time {
                        GeneralizedTime::new(
                            rt.year(),
                            rt.month(),
                            rt.day(),
                            rt.hour(),
                            rt.minute(),
                            rt.second(),
                        ).unwrap_or(time)
                    } else {
                        time
                    };

                    let motif = record.revocation_reason.clone().unwrap_or_default();
                    let motif: CrlReason = match motif.as_str() {
                        "key_compromise" => CrlReason::OcspRevokeKeyCompromise,
                        "ca_compromise" => CrlReason::OcspRevokeCaCompromise,
                        "affiliation_changed" => CrlReason::OcspRevokeAffChanged,
                        "superseded" => CrlReason::OcspRevokeSuperseded,
                        "cessation_of_operation" => CrlReason::OcspRevokeCessOperation,
                        "certificate_hold" => CrlReason::OcspRevokeCertHold,
                        "privilege_withdrawn" => CrlReason::OcspRevokePrivWithdrawn,
                        "aa_compromise" => CrlReason::OcspRevokeAaCompromise,
                        _ => CrlReason::OcspRevokeUnspecified,
                    };

                    Ok(OcspCertStatus::new(
                        CertStatusCode::Revoked,
                        Some(RevokedInfo::new(time, Some(motif))),
                    ))
                } else {
                    Ok(OcspCertStatus::new(CertStatusCode::Good, None))
                }
            }
        }).await??;

        Ok(result)
    }

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = self.get_connection()?;
        let query = format!("SHOW TABLES LIKE '{}'", self.table_name);

        // For checking if table exists, we'll use execute instead of load for simpler handling
        let exists: bool = diesel::sql_query(query)
            .execute(&mut conn)
            .map(|count| count > 0)?;

        if exists {
            info!("Table {} already exists in MySQL database", self.table_name);
            return Ok(());
        }

        let create_table_query = format!(
            "CREATE TABLE `{}` (
                `cert_num` varchar(50) NOT NULL,
                `revocation_time` datetime DEFAULT NULL,
                `revocation_reason` enum('unspecified','key_compromise','ca_compromise','affiliation_changed','superseded','cessation_of_operation','certificate_hold','privilege_withdrawn','aa_compromise') DEFAULT NULL,
                `status` enum('Valid','Revoked') NOT NULL DEFAULT 'Valid',
                PRIMARY KEY (`cert_num`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            self.table_name
        );

        diesel::sql_query(create_table_query).execute(&mut conn)?;

        info!(
            "Table {} created successfully in MySQL database",
            self.table_name
        );
        Ok(())
    }

    async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = self.pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Check if certificate already exists
            let query = format!(
                "SELECT COUNT(*) as count FROM {} WHERE cert_num = ?",
                table_name
            );

            let exists: bool = diesel::sql_query(query.clone())
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?
                > 0;

            if exists {
                return Err("Certificate already exists".into());
            }

            // Insert new certificate
            let insert_query = format!(
                "INSERT INTO {} (cert_num, status) VALUES (?, 'Valid')",
                table_name
            );

            diesel::sql_query(insert_query)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?;

            Ok(())
        })
        .await?
    }

    async fn revoke_certificate(
        &self,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = chrono::Utc::now().naive_utc();
        if revocation_time > now {
            return Err("Revocation time cannot be in the future".into());
        }

        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let reason = reason.to_string();
        let connection_manager = self.pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Check if certificate exists
            let query = format!(
                "SELECT COUNT(*) as count FROM {} WHERE cert_num = ?",
                table_name
            );

            let exists: bool = diesel::sql_query(query.clone())
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?
                > 0;

            if !exists {
                return Err("Certificate does not exist".into());
            }

            // Update certificate status
            let update_query = format!(
                "UPDATE {} SET status = 'Revoked', revocation_time = ?, revocation_reason = ? WHERE cert_num = ?",
                table_name
            );

            diesel::sql_query(update_query)
                .bind::<sql_types::Timestamp, _>(&revocation_time)
                .bind::<sql_types::Text, _>(&reason)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?;

            Ok(())
        }).await?
    }

    async fn get_certificate_status(
        &self,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Query certificate status
            let query = format!(
                "SELECT cert_num, status, revocation_time, revocation_reason FROM {} WHERE cert_num = ?",
                table_name
            );

            let records = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<CertRecord>(&mut conn)?;

            if records.is_empty() {
                return Err("Certificate not found".into());
            }

            let record = &records[0];

            Ok(Certinfo {
                status: record.status.clone(),
                revocation_time: record.revocation_time,
                revocation_reason: record.revocation_reason.clone(),
            })
        }).await??;

        Ok(result)
    }

    async fn list_certificates(
        &self,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let status_filter = status.map(|s| s.to_string());
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(
            move || -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
                let mut conn = connection_manager.get()?;

                // Build query based on status filter (MySQL)
                let query = match &status_filter {
                    Some(_s) => format!(
                        "SELECT cert_num, status, revocation_time, revocation_reason FROM {} WHERE status = ?",
                        table_name
                    ),
                    None => format!("SELECT cert_num, status, revocation_time, revocation_reason FROM {}", table_name),
                };

                // Execute query with or without filter
                let records: Vec<CertRecord> = if let Some(s) = &status_filter {
                    diesel::sql_query(query)
                        .bind::<sql_types::Text, _>(s)
                        .load::<CertRecord>(&mut conn)?
                } else {
                    diesel::sql_query(query).load::<CertRecord>(&mut conn)?
                };

                // Convert to response format
                let responses = records
                    .into_iter()
                    .map(|record| CertificateResponse {
                        cert_num: record.cert_num,
                        status: record.status,
                        message: String::new(),
                    })
                    .collect();

                Ok(responses)
            },
        )
        .await??;

        Ok(result)
    }
}

pub struct DieselPgDatabase {
    config: Arc<Config>,
    pool: PgPool,
    table_name: String,
}

impl DieselPgDatabase {
    pub fn new(config: Arc<Config>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let database_url = match &config.dbip {
            Some(host) => format!(
                "postgres://{}:{}@{}:{}/{}",
                config.dbuser,
                config.dbpassword,
                host,
                config.dbport.unwrap_or(DEFAULT_POSTGRES_PORT),
                config.dbname
            ),
            None => format!(
                "postgres://{}:{}@localhost/{}",
                config.dbuser, config.dbpassword, config.dbname
            ),
        };

        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(15)
            .connection_timeout(Duration::from_secs(config.time as u64))
            .build(manager)?;

        let table_name = config
            .table_name
            .clone()
            .unwrap_or_else(|| DEFAULT_POSTGRES_TABLE.to_string());

        Ok(Self {
            config,
            pool,
            table_name,
        })
    }

    fn get_connection(
        &self,
    ) -> Result<
        diesel::r2d2::PooledConnection<ConnectionManager<PgConnection>>,
        Box<dyn Error + Send + Sync>,
    > {
        Ok(self.pool.get()?)
    }
}

#[async_trait]
impl Database for DieselPgDatabase {
    async fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = certnum.to_string();
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Using text SQL query with explicit column names and types
            let query = format!(
                "SELECT cert_num, revocation_time, revocation_reason, status FROM {} WHERE cert_num = $1",
                table_name
            );

            let results = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<CertRecord>(&mut conn)?;

            if results.is_empty() {
                warn!("Entry not found for cert {} in PostgreSQL", cert_num);
                if !revoked {
                    Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
                } else {
                    Ok(OcspCertStatus::new(
                        CertStatusCode::Revoked,
                        Some(RevokedInfo::new(
                            GeneralizedTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
                            Some(CrlReason::OcspRevokeCertHold),
                        )),
                    ))
                }
            } else {
                let record = &results[0];
                debug!("Entry found for cert {}, status {}", cert_num, record.status);

                if record.status == "Revoked" {
                    let time = GeneralizedTime::now();

                    let time = if let Some(rt) = record.revocation_time {
                        GeneralizedTime::new(
                            rt.year(),
                            rt.month(),
                            rt.day(),
                            rt.hour(),
                            rt.minute(),
                            rt.second(),
                        ).unwrap_or(time)
                    } else {
                        time
                    };

                    let motif = record.revocation_reason.clone().unwrap_or_default();
                    let motif: CrlReason = match motif.as_str() {
                        "key_compromise" => CrlReason::OcspRevokeKeyCompromise,
                        "ca_compromise" => CrlReason::OcspRevokeCaCompromise,
                        "affiliation_changed" => CrlReason::OcspRevokeAffChanged,
                        "superseded" => CrlReason::OcspRevokeSuperseded,
                        "cessation_of_operation" => CrlReason::OcspRevokeCessOperation,
                        "certificate_hold" => CrlReason::OcspRevokeCertHold,
                        "privilege_withdrawn" => CrlReason::OcspRevokePrivWithdrawn,
                        "aa_compromise" => CrlReason::OcspRevokeAaCompromise,
                        _ => CrlReason::OcspRevokeUnspecified,
                    };

                    Ok(OcspCertStatus::new(
                        CertStatusCode::Revoked,
                        Some(RevokedInfo::new(time, Some(motif))),
                    ))
                } else {
                    Ok(OcspCertStatus::new(CertStatusCode::Good, None))
                }
            }
        }).await??;

        Ok(result)
    }

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = self.get_connection()?;

        // Using a simpler check query that works well with QueryableByName
        let exists_query = format!(
            "SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = '{}'
            ) as exists",
            self.table_name
        );

        let exists_results = diesel::sql_query(exists_query).load::<BoolResult>(&mut conn)?;

        let exists = !exists_results.is_empty() && exists_results[0].exists;

        if exists {
            info!(
                "Table {} already exists in PostgreSQL database",
                self.table_name
            );
            return Ok(());
        }

        // Check if types exist with a properly formatted query
        let types_exist_query = "SELECT EXISTS (
                SELECT FROM pg_type
                WHERE typname = 'cert_status'
            ) as exists";

        let types_exist_results =
            diesel::sql_query(types_exist_query).load::<BoolResult>(&mut conn)?;

        let types_exist = !types_exist_results.is_empty() && types_exist_results[0].exists;

        if !types_exist {
            // Split into two separate queries to avoid issues
            diesel::sql_query("CREATE TYPE cert_status AS ENUM ('Valid', 'Revoked');")
                .execute(&mut conn)?;

            diesel::sql_query(
                "CREATE TYPE revocation_reason_enum AS ENUM (
                    'unspecified',
                    'key_compromise',
                    'ca_compromise',
                    'affiliation_changed',
                    'superseded',
                    'cessation_of_operation',
                    'certificate_hold',
                    'privilege_withdrawn',
                    'aa_compromise'
                );",
            )
            .execute(&mut conn)?;
        }

        diesel::sql_query(format!(
            "CREATE TABLE {} (
                cert_num VARCHAR(50) PRIMARY KEY,
                revocation_time TIMESTAMP DEFAULT NULL,
                revocation_reason revocation_reason_enum DEFAULT NULL,
                status cert_status NOT NULL DEFAULT 'Valid'
            );",
            self.table_name
        ))
        .execute(&mut conn)?;

        info!(
            "Table {} created successfully in PostgreSQL database",
            self.table_name
        );
        Ok(())
    }

    async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = self.pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Check if certificate already exists
            let query = format!(
                "SELECT EXISTS (SELECT 1 FROM {} WHERE cert_num = $1) as exists",
                table_name
            );

            let exists_results = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<BoolResult>(&mut conn)?;

            let exists = !exists_results.is_empty() && exists_results[0].exists;

            if exists {
                return Err("Certificate already exists".into());
            }

            // Insert new certificate
            let insert_query = format!(
                "INSERT INTO {} (cert_num, status) VALUES ($1, 'Valid')",
                table_name
            );

            diesel::sql_query(insert_query)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?;

            Ok(())
        })
        .await?
    }

    async fn revoke_certificate(
        &self,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = chrono::Utc::now().naive_utc();
        if revocation_time > now {
            return Err("Revocation time cannot be in the future".into());
        }

        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let reason = reason.to_string();
        let connection_manager = self.pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Check if certificate exists
            let query = format!(
                "SELECT EXISTS (SELECT 1 FROM {} WHERE cert_num = $1) as exists",
                table_name
            );

            let exists_results = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<BoolResult>(&mut conn)?;

            let exists = !exists_results.is_empty() && exists_results[0].exists;

            if !exists {
                return Err("Certificate does not exist".into());
            }

            // Update certificate status
            // For PostgreSQL, we need to cast the text to the enum type
            let update_query = format!(
                "UPDATE {} SET status = 'Revoked', revocation_time = $1, revocation_reason = $2::revocation_reason_enum WHERE cert_num = $3",
                table_name
            );

            diesel::sql_query(update_query)
                .bind::<sql_types::Timestamp, _>(&revocation_time)
                .bind::<sql_types::Text, _>(&reason)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?;

            Ok(())
        }).await?
    }

    async fn get_certificate_status(
        &self,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            // Query certificate status
            let query = format!(
                "SELECT cert_num, status, revocation_time, revocation_reason FROM {} WHERE cert_num = $1",
                table_name
            );

            let records = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .load::<CertRecord>(&mut conn)?;

            if records.is_empty() {
                return Err("Certificate not found".into());
            }

            let record = &records[0];

            Ok(Certinfo {
                status: record.status.clone(),
                revocation_time: record.revocation_time,
                revocation_reason: record.revocation_reason.clone(),
            })
        }).await??;

        Ok(result)
    }

    async fn list_certificates(
        &self,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let status_filter = status.map(|s| s.to_string());
        let connection_manager = self.pool.clone();

        let result = tokio::task::spawn_blocking(
            move || -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
                let mut conn = connection_manager.get()?;

                // Build query based on status filter (PostgreSQL)
                let query = match &status_filter {
                    Some(_s) => format!(
                        "SELECT cert_num, status, revocation_time, revocation_reason FROM {} WHERE status = $1::cert_status",
                        table_name
                    ),
                    None => format!("SELECT cert_num, status, revocation_time, revocation_reason FROM {}", table_name),
                };

                // Execute query with or without filter
                let records: Vec<CertRecord> = if let Some(s) = &status_filter {
                    diesel::sql_query(query)
                        .bind::<sql_types::Text, _>(s)
                        .load::<CertRecord>(&mut conn)?
                } else {
                    diesel::sql_query(query).load::<CertRecord>(&mut conn)?
                };

                // Convert to response format
                let responses = records
                    .into_iter()
                    .map(|record| CertificateResponse {
                        cert_num: record.cert_num,
                        status: record.status,
                        message: String::new(),
                    })
                    .collect();

                Ok(responses)
            },
        )
        .await??;

        Ok(result)
    }
}

pub fn create_database(
    config: Arc<Config>,
) -> Result<Box<dyn Database>, Box<dyn Error + Send + Sync>> {
    match DatabaseType::from_string(&config.db_type) {
        DatabaseType::MySQL => {
            let db = DieselMysqlDatabase::new(config)?;
            Ok(Box::new(db))
        }
        DatabaseType::PostgreSQL => {
            let db = DieselPgDatabase::new(config)?;
            Ok(Box::new(db))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::*;

    mock! {
        pub Database {}

        #[async_trait]
        impl Database for Database {
            async fn check_cert(
                &self,
                certnum: &str,
                revoked: bool,
            ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>>;

            fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>>;

            async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

            async fn revoke_certificate(
                &self,
                cert_num: &str,
                revocation_time: NaiveDateTime,
                reason: &str,
            ) -> Result<(), Box<dyn Error + Send + Sync>>;

            async fn get_certificate_status(&self, cert_num: &str) -> Result<Certinfo, Box<dyn Error + Send + Sync>>;

            async fn list_certificates(
                &self,
                status: Option<String>,
            ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>>;
        }
    }

    #[test]
    fn test_database_type_from_string() {
        assert!(matches!(
            DatabaseType::from_string("mysql"),
            DatabaseType::MySQL
        ));
        assert!(matches!(
            DatabaseType::from_string("MySQL"),
            DatabaseType::MySQL
        ));
        assert!(matches!(
            DatabaseType::from_string("postgresql"),
            DatabaseType::PostgreSQL
        ));
        assert!(matches!(
            DatabaseType::from_string("postgres"),
            DatabaseType::PostgreSQL
        ));
        assert!(matches!(
            DatabaseType::from_string("PostgreSQL"),
            DatabaseType::PostgreSQL
        ));
        assert!(matches!(
            DatabaseType::from_string("unknown"),
            DatabaseType::MySQL
        ));
    }

    #[test]
    fn test_default_table_names() {
        assert_eq!(
            DatabaseType::MySQL.default_table_name(),
            DEFAULT_MYSQL_TABLE
        );
        assert_eq!(
            DatabaseType::PostgreSQL.default_table_name(),
            DEFAULT_POSTGRES_TABLE
        );
    }
}
