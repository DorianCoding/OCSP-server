use chrono::NaiveDateTime;
//use chrono::NaiveDateTime;
use clap::{crate_authors, Parser};
use diesel::QueryableByName;
use ocsp::common::asn1::Bytes;
//use ocsp::common::asn1::Bytes;
use serde::{Deserialize, Serialize};
//use x509_parser::prelude::X509Certificate;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[clap(
    author = crate_authors!("\n"),
    before_help = "This script listens and answers to OCSP requests/response.",
    after_help = "A config file is required for the script to work.",
    help_template = "\
    {name} {version}
    Authors: {author-section}
    {before-help}
    About: {about-with-newline}
    {usage-heading} {usage}

    {all-args}{after-help}
    "
)]
#[command(version, author, about, long_about = None)]
pub(crate) struct Cli {
    #[arg(default_value = "config.toml")]
    pub(crate) config_path: String,
}

pub(crate) const CACHEFORMAT: &str = "%Y-%m-%d-%H-%M-%S";
pub(crate) const DEFAULT_PORT: u16 = 9000;
pub(crate) const DEFAULT_LISTEN_IP: &str = "localhost";
pub(crate) const DEFAULT_TIMEOUT: u8 = 5;
#[cfg(feature = "mysql")]
pub(crate) const DEFAULT_MYSQL_PORT: u16 = 3306;
#[cfg(feature = "postgres")]
pub(crate) const DEFAULT_POSTGRES_PORT: u16 = 5432;
#[cfg(feature = "mysql")]
pub(crate) const DEFAULT_MYSQL_TABLE: &str = DEFAULT_SQLITE_TABLE;
#[cfg(feature = "postgres")]
pub(crate) const DEFAULT_POSTGRES_TABLE: &str = DEFAULT_SQLITE_TABLE;
pub(crate) const DEFAULT_SQLITE_TABLE: &str = "list_certs";

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) issuer_hash: (Vec<u8>, Vec<u8>, bool),
    pub(crate) cert: Bytes,
    pub(crate) revocextended: bool,
    pub(crate) time: u8,
    pub(crate) rsakey: ring::signature::RsaKeyPair,
    pub(crate) cachedays: u16,
    pub(crate) caching: bool,
    pub(crate) dbip: Option<String>,
    pub(crate) dbuser: String,
    pub(crate) dbpassword: String,
    pub(crate) dbname: String,
    pub(crate) db_type: String,
    #[cfg(any(feature = "mysql",feature="postgres"))]
    pub(crate) dbport: Option<u16>,
    pub(crate) create_table: bool,
    pub(crate) cachefolder: String,
    pub(crate) table_name: Option<String>,
    pub(crate) api_keys: Option<Vec<String>>,
    pub(crate) enable_api: bool,
    pub(crate) listen_ip: String,
}

// Don't implement Default for Config, because we can't easily create a dummy RsaKeyPair.
// We'll use explicit constructors in tests instead.

impl Drop for Config {
    fn drop(&mut self) {
        self.dbip.zeroize();
        self.dbuser.zeroize();
        self.dbpassword.zeroize();
        self.dbname.zeroize();
    }
}

#[derive(Deserialize)]
pub(crate) struct Fileconfig {
    pub(crate) cachedays: u16,
    pub(crate) caching: Option<bool>,
    pub(crate) revocextended: Option<bool>,
    pub(crate) dbip: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) listen_ip: Option<String>,
    pub(crate) timeout: Option<u8>,
    pub(crate) dbuser: String,
    pub(crate) dbpassword: String,
    pub(crate) dbname: String,
    pub(crate) db_type: Option<String>,
    #[allow(dead_code)]
    pub(crate) dbport: Option<u16>,
    pub(crate) create_table: Option<bool>,
    pub(crate) cachefolder: String,
    pub(crate) itkey: String,
    pub(crate) itcert: String,
    pub(crate) table_name: Option<String>,
    pub(crate) api_keys: Option<Vec<String>>,
    pub(crate) enable_api: Option<bool>,
}

impl Drop for Fileconfig {
    fn drop(&mut self) {
        self.dbip.zeroize();
        self.dbuser.zeroize();
        self.dbpassword.zeroize();
        self.dbname.zeroize();
    }
}

#[derive(Debug, PartialEq, Clone)]
#[allow(dead_code)]
pub(crate) struct Certinfo {
    pub(crate) status: String,
    pub(crate) revocation_time: Option<chrono::NaiveDateTime>,
    pub(crate) revocation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, QueryableByName)]
pub(crate) struct CertRecord {
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) cert_num: String,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamp>)]
    pub(crate) revocation_time: Option<chrono::NaiveDateTime>,

    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) revocation_reason: Option<String>,

    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) status: String,
}
#[cfg(feature = "postgres")]
#[derive(Debug, QueryableByName)]
pub(crate) struct BoolResult {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) exists: bool,
}

// API Authentication
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ApiKey(pub(crate) String);

// API Request and Response Structures
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CertificateRequest {
    pub cert_num: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RevocationRequest {
    pub(crate) cert_num: String,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_time: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CertificateResponse {
    pub(crate) cert_num: String,
    pub(crate) status: String,
    pub(crate) message: String,
}
