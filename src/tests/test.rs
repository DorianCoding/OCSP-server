use crate::database::DatabaseType;
use crate::{rocket, DEFAULT_SQLITE_TABLE};
#[cfg(feature = "mysql")]
use crate::DEFAULT_MYSQL_TABLE;
#[cfg(feature = "postgres")]
use crate::DEFAULT_POSTGRES_TABLE;
use crate::{Cli, Fileconfig, getprivatekey};
use clap::Parser;
use config_file::FromConfigFile;
use mockall::*;
use ring::{rand, signature};
use rocket::async_trait;
use std::{fs, path::Path};
use zeroize::Zeroize;
use crate::Database;
#[test]
fn testresponse() {
    use ring::rand::SecureRandom;
    use ring::signature::KeyPair;
    use std::time::Instant;
    println!("Generating key, may take a while...");
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    println!("Done.");
    let mut tosign = [0u8; 3000];
    println!("Generating random");
    rng.fill(&mut tosign).unwrap();
    println!("Done!");
    let time = Instant::now();
    for i in 0..100 {
        if i % 10 == 0 {
            rng.fill(&mut tosign).unwrap();
        }
        let sig = key_pair.sign(&tosign);
        // Normally an application would extract the bytes of the signature and
        // send them in a protocol message to the peer(s). Here we just get the
        // public key key directly from the key pair.
        let peer_public_key_bytes = key_pair.public_key().as_ref();

        // Verify the signature of the message using the public key. Normally the
        // verifier of the message would parse the inputs to this code out of the
        // protocol message(s) sent by the signer.
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
        peer_public_key.verify(&tosign, sig.as_ref()).unwrap();
    }
    println!("Elapsed time : {:.6} ms", time.elapsed().as_millis());
}
#[test]
#[should_panic(
    expected = "Error creating KeyPair from PEM."
)]
fn checkconfigfake() {
    let cli = Cli::parse();

    let config_path = &cli.config_path;

    if !Path::new(config_path).exists() {
        panic!("Config file not found at: {}", config_path.display());
    }

    let mut config = match Fileconfig::from_config_file(config_path) {
        Ok(config) => config,
        Err(e) => {
            panic!("Error reading config file at {}: {}", config_path.display(), e);
        }
    };
    config.itkey = String::from("test_files/key.pem");
    //For an unknown reason, subject key identifier is not equal to SHA1 hash key so it is used instead.
    //let issuer_name_hash = certpem.subject_name_hash();
    let mut key = fs::read(&config.itkey).unwrap();
    let _rsakey = getprivatekey(&key).unwrap();
    key.zeroize();
}
#[test]
fn checkconfig() {
    rocket();
}
mock! {
    pub Database {}

    #[async_trait]
    impl Database for Database {
        async fn check_cert(
            &self,
            certnum: &str,
            revoked: bool,
        ) -> Result<ocsp::response::CertStatus, Box<dyn std::error::Error + Send + Sync>>;

        fn create_tables_if_needed(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

        async fn add_certificate(&self, cert_num: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

        async fn revoke_certificate(
            &self,
            cert_num: &str,
            revocation_time: chrono::NaiveDateTime,
            reason: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

        async fn get_certificate_status(&self, cert_num: &str) -> Result<crate::Certinfo, Box<dyn std::error::Error + Send + Sync>>;

        async fn list_certificates(
            &self,
            status: Option<String>,
        ) -> Result<Vec<crate::CertificateResponse>, Box<dyn std::error::Error + Send + Sync>>;
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
        DatabaseType::from_string("sqlite"),
        DatabaseType::SQLite
    ));
    assert!(matches!(
        DatabaseType::from_string("SQLite"),
        DatabaseType::SQLite
    ));
    assert!(matches!(
        DatabaseType::from_string("unknown"),
        DatabaseType::SQLite
    ));
}

#[test]
fn test_default_table_names() {
    #[cfg(feature="mysql")]
    assert_eq!(
        DatabaseType::MySQL.default_table_name(),
        DEFAULT_MYSQL_TABLE
    );
    #[cfg(feature="postgres")]
    assert_eq!(
        DatabaseType::PostgreSQL.default_table_name(),
        DEFAULT_POSTGRES_TABLE
    );
    assert_eq!(
        DatabaseType::SQLite.default_table_name(),
        DEFAULT_SQLITE_TABLE
    );
}
