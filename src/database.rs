use crate::r#struct::{
    CertRecord, CertificateResponse, Certinfo, Config, DEFAULT_SQLITE_TABLE,
};
#[cfg(feature="mysql")]
use crate::r#struct::DEFAULT_MYSQL_PORT;
#[cfg(feature="mysql")]
use crate::r#struct::DEFAULT_MYSQL_TABLE;
#[cfg(feature="postgres")]
use crate::r#struct::DEFAULT_POSTGRES_PORT;
#[cfg(feature="postgres")]
use crate::r#struct::DEFAULT_POSTGRES_TABLE;
use async_trait::async_trait;
use chrono::{Datelike, NaiveDateTime, Timelike};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sql_types;
use diesel::SqliteConnection;
#[cfg(feature = "mysql")]
use diesel::MysqlConnection;
#[cfg(feature = "postgres")]
use diesel::PgConnection;
#[cfg(feature = "postgres")]
use crate::BoolResult;
use log::{debug, info, warn};
use ocsp::common::asn1::GeneralizedTime;
use ocsp::response::{CertStatus as OcspCertStatus, CertStatusCode, CrlReason, RevokedInfo};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
}

impl DatabaseType {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mysql" | "MySql" => DatabaseType::MySQL,
            "postgres" | "postgresql" => DatabaseType::PostgreSQL,
            _ => DatabaseType::SQLite,
        }
    }
    #[cfg(any(feature = "mysql",feature="postgres"))]
    fn default_port(&self) -> u16 {
        match self {
            DatabaseType::MySQL => DEFAULT_MYSQL_PORT,
            DatabaseType::PostgreSQL => DEFAULT_POSTGRES_PORT,
            DatabaseType::SQLite => 0,
        }
    }

    pub fn default_table_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "mysql")]
            DatabaseType::MySQL => DEFAULT_MYSQL_TABLE,
            #[cfg(feature = "postgres")]
            DatabaseType::PostgreSQL => DEFAULT_POSTGRES_TABLE,
            _ => DEFAULT_SQLITE_TABLE,
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

enum DatabaseConnection {
    #[cfg(feature = "mysql")]
    MySQL(Pool<ConnectionManager<MysqlConnection>>),
    #[cfg(feature = "postgres")]
    PostgreSQL(Pool<ConnectionManager<PgConnection>>),
    SQLite(Pool<ConnectionManager<SqliteConnection>>),
}

pub struct DieselDatabase {
    connection: DatabaseConnection,
    config: Arc<Config>,
    table_name: String,
}

impl DieselDatabase {
    pub fn new(config: Arc<Config>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let db_type = DatabaseType::from_string(&config.db_type);
        let table_name = config
            .table_name
            .clone()
            .unwrap_or_else(|| db_type.default_table_name().to_string());

        let connection = match db_type {
            #[cfg(feature="mysql")]
            DatabaseType::MySQL => {
                let dbport = config.dbport.unwrap_or_else(|| db_type.default_port());
                let database_url = match &config.dbip {
                    Some(host) => format!(
                        "mysql://{}:{}@{}:{}/{}",
                        config.dbuser, config.dbpassword, host, dbport, config.dbname
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

                DatabaseConnection::MySQL(pool)
            }
            #[cfg(feature="postgres")]
            DatabaseType::PostgreSQL => {
                let dbport = config.dbport.unwrap_or_else(|| db_type.default_port());
                let database_url = match &config.dbip {
                    Some(host) => format!(
                        "postgres://{}:{}@{}:{}/{}",
                        config.dbuser, config.dbpassword, host, dbport, config.dbname
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

                DatabaseConnection::PostgreSQL(pool)
            }
            _ => {
                let db_path = &config.dbname;

                if let Some(parent) = Path::new(db_path).parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)?;
                    }
                }

                let database_url = format!("sqlite://{}", db_path);

                let manager = ConnectionManager::<SqliteConnection>::new(database_url);
                let pool = Pool::builder()
                    .max_size(1)
                    .connection_timeout(Duration::from_secs(config.time as u64))
                    .build(manager)?;

                DatabaseConnection::SQLite(pool)
            }
        };

        Ok(Self {
            connection,
            config,
            table_name,
        })
    }
    #[cfg(feature="mysql")]
    async fn check_cert_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = certnum.to_string();
        let connection_manager = pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

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
    #[cfg(feature="postgres")]
    async fn check_cert_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = certnum.to_string();
        let connection_manager = pool.clone();

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

    async fn check_cert_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = certnum.to_string();
        let connection_manager = pool.clone();

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
                warn!("Entry not found for cert {} in SQLite", cert_num);
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
    #[cfg(feature="mysql")]
    fn create_tables_if_needed_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = pool.get()?;
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
    #[cfg(feature="postgres")]
    fn create_tables_if_needed_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = pool.get()?;

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

        let types_exist_query = "SELECT EXISTS (
                SELECT FROM pg_type
                WHERE typname = 'cert_status'
            ) as exists";

        let types_exist_results =
            diesel::sql_query(types_exist_query).load::<BoolResult>(&mut conn)?;

        let types_exist = !types_exist_results.is_empty() && types_exist_results[0].exists;

        if !types_exist {
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

    fn create_tables_if_needed_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.create_table {
            return Ok(());
        }

        let mut conn = pool.get()?;

        let exists_query = format!(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
            self.table_name
        );

        let exists: bool = diesel::sql_query(exists_query)
            .execute(&mut conn)
            .map(|count| count > 0)?;

        if exists {
            info!(
                "Table {} already exists in SQLite database",
                self.table_name
            );
            return Ok(());
        }

        let create_table_query = format!(
            "CREATE TABLE {} (
                cert_num TEXT PRIMARY KEY,
                revocation_time TIMESTAMP DEFAULT NULL,
                revocation_reason TEXT DEFAULT NULL CHECK(
                    revocation_reason IS NULL OR
                    revocation_reason IN ('unspecified', 'key_compromise', 'ca_compromise',
                                     'affiliation_changed', 'superseded', 'cessation_of_operation',
                                     'certificate_hold', 'privilege_withdrawn', 'aa_compromise')
                ),
                status TEXT NOT NULL DEFAULT 'Valid' CHECK(status IN ('Valid', 'Revoked'))
            )",
            self.table_name
        );

        diesel::sql_query(create_table_query).execute(&mut conn)?;

        info!(
            "Table {} created successfully in SQLite database",
            self.table_name
        );
        Ok(())
    }
    #[cfg(feature="mysql")]
    async fn add_certificate_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
        cert_num: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

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
    #[cfg(feature="postgres")]
    async fn add_certificate_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
        cert_num: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

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

    async fn add_certificate_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        cert_num: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            let query = format!(
                "SELECT COUNT(*) as count FROM {} WHERE cert_num = ?",
                table_name
            );

            let exists: bool = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?
                > 0;

            if exists {
                return Err("Certificate already exists".into());
            }

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
    #[cfg(feature="mysql")]
    async fn revoke_certificate_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let reason = reason.to_string();
        let connection_manager = pool.clone();

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
    #[cfg(feature="postgres")]
    async fn revoke_certificate_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let reason = reason.to_string();
        let connection_manager = pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

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

    async fn revoke_certificate_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        cert_num: &str,
        revocation_time: NaiveDateTime,
        reason: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let reason = reason.to_string();
        let connection_manager = pool.clone();

        tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

            let query = format!(
                "SELECT COUNT(*) as count FROM {} WHERE cert_num = ?",
                table_name
            );

            let exists: bool = diesel::sql_query(query)
                .bind::<sql_types::Text, _>(&cert_num)
                .execute(&mut conn)?
                > 0;

            if !exists {
                return Err("Certificate does not exist".into());
            }

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
    #[cfg(feature="mysql")]
    async fn get_certificate_status_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

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
    #[cfg(feature="postgres")]
    async fn get_certificate_status_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

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

    async fn get_certificate_status_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let cert_num = cert_num.to_string();
        let connection_manager = pool.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
            let mut conn = connection_manager.get()?;

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
    #[cfg(feature="mysql")]
    async fn list_certificates_mysql(
        &self,
        pool: &Pool<ConnectionManager<MysqlConnection>>,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let status_filter = status.map(|s| s.to_string());
        let connection_manager = pool.clone();

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
    #[cfg(feature="postgres")]
    async fn list_certificates_postgres(
        &self,
        pool: &Pool<ConnectionManager<PgConnection>>,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let status_filter = status.map(|s| s.to_string());
        let connection_manager = pool.clone();

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

    async fn list_certificates_sqlite(
        &self,
        pool: &Pool<ConnectionManager<SqliteConnection>>,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        let table_name = self.table_name.clone();
        let status_filter = status.map(|s| s.to_string());
        let connection_manager = pool.clone();

        let result = tokio::task::spawn_blocking(
            move || -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
                let mut conn = connection_manager.get()?;

                let query = match &status_filter {
                    Some(_s) => format!(
                        "SELECT cert_num, status, revocation_time, revocation_reason FROM {} WHERE status = ?",
                        table_name
                    ),
                    None => format!("SELECT cert_num, status, revocation_time, revocation_reason FROM {}", table_name),
                };

                let records: Vec<CertRecord> = if let Some(s) = &status_filter {
                    diesel::sql_query(query)
                        .bind::<sql_types::Text, _>(s)
                        .load::<CertRecord>(&mut conn)?
                } else {
                    diesel::sql_query(query).load::<CertRecord>(&mut conn)?
                };

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

#[async_trait]
impl Database for DieselDatabase {
    async fn check_cert(
        &self,
        certnum: &str,
        revoked: bool,
    ) -> Result<OcspCertStatus, Box<dyn Error + Send + Sync>> {
        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => self.check_cert_mysql(pool, certnum, revoked).await,
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => {
                self.check_cert_postgres(pool, certnum, revoked).await
            }
            DatabaseConnection::SQLite(pool) => {
                self.check_cert_sqlite(pool, certnum, revoked).await
            }
        }
    }

    fn create_tables_if_needed(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => self.create_tables_if_needed_mysql(pool),
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => self.create_tables_if_needed_postgres(pool),
            DatabaseConnection::SQLite(pool) => self.create_tables_if_needed_sqlite(pool),
        }
    }

    async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => self.add_certificate_mysql(pool, cert_num).await,
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => {
                self.add_certificate_postgres(pool, cert_num).await
            }
            DatabaseConnection::SQLite(pool) => self.add_certificate_sqlite(pool, cert_num).await,
        }
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

        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => {
                self.revoke_certificate_mysql(pool, cert_num, revocation_time, reason)
                    .await
            }
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => {
                self.revoke_certificate_postgres(pool, cert_num, revocation_time, reason)
                    .await
            }
            DatabaseConnection::SQLite(pool) => {
                self.revoke_certificate_sqlite(pool, cert_num, revocation_time, reason)
                    .await
            }
        }
    }

    async fn get_certificate_status(
        &self,
        cert_num: &str,
    ) -> Result<Certinfo, Box<dyn Error + Send + Sync>> {
        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => {
                self.get_certificate_status_mysql(pool, cert_num).await
            }
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => {
                self.get_certificate_status_postgres(pool, cert_num).await
            }
            DatabaseConnection::SQLite(pool) => {
                self.get_certificate_status_sqlite(pool, cert_num).await
            }
        }
    }

    async fn list_certificates(
        &self,
        status: Option<String>,
    ) -> Result<Vec<CertificateResponse>, Box<dyn Error + Send + Sync>> {
        match &self.connection {
            #[cfg(feature="mysql")]
            DatabaseConnection::MySQL(pool) => self.list_certificates_mysql(pool, status).await,
            #[cfg(feature="postgres")]
            DatabaseConnection::PostgreSQL(pool) => {
                self.list_certificates_postgres(pool, status).await
            }
            DatabaseConnection::SQLite(pool) => self.list_certificates_sqlite(pool, status).await,
        }
    }
}

pub fn create_database(
    config: Arc<Config>,
) -> Result<Box<dyn Database>, Box<dyn Error + Send + Sync>> {
    let db = DieselDatabase::new(config)?;
    Ok(Box::new(db))
}