extern crate rocket;

use chrono::{self, NaiveDateTime, Timelike};
use chrono::{DateTime, Datelike, FixedOffset};
use clap::{CommandFactory, Parser};
use config_file::FromConfigFile;
use log::{debug, error, info, trace, warn};
use ocsp::common::asn1::Bytes;
use ocsp::common::ocsp::{OcspExt, OcspExtI};
use ocsp::request::OcspRequest;
use ocsp::{
    common::asn1::{CertId, GeneralizedTime, Oid},
    err::OcspError,
    oid::{ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT, OCSP_RESPONSE_BASIC_DOT},
    response::{
        BasicResponse, CertStatus, CertStatusCode, OcspRespStatus, OcspResponse, OneResp,
        ResponderId, ResponseBytes, ResponseData,
    },
};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use pem::parse;
use r#struct::*;
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
use ring::{rand, signature};
use rocket::http::ContentType;
use rocket::State;
use rocket::{data::ToByteUnit, Data};
use rocket::{get, launch, post, routes};
use std::error::Error;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
use x509_parser::prelude::ParsedExtension;
use zeroize::Zeroize;

mod api;
mod database;
mod r#struct;

use database::Database;

fn signresponse(
    issuer_hash: &[u8],
    private_key: &ring::signature::RsaKeyPair,
    response: Vec<OneResp>,
    extensions: Option<Vec<OcspExtI>>,
    cert: Option<Vec<Bytes>>,
) -> Result<ResponseBytes, Box<dyn std::error::Error>> {
    let id = ResponderId::new_key_hash(issuer_hash); // responding by id
    let produce = GeneralizedTime::now();
    let data = ResponseData::new(id, produce, response, extensions);
    let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT)?;
    let rng = rand::SystemRandom::new();
    let tosign = &data.to_der()?;
    let mut signature = vec![0u8; private_key.public().modulus_len()];
    private_key
        .sign(&signature::RSA_PKCS1_SHA256, &rng, tosign, &mut signature)
        .unwrap();
    assert_ne!(&signature, tosign);
    let basic = BasicResponse::new(data, oid, signature, cert);
    // equivalent to
    // let resp_type = Oid::new_from_dot("1.3.6.1.5.5.7.48.1.1").await?;
    let resp_type = Oid::new_from_dot(OCSP_RESPONSE_BASIC_DOT)?;
    let bytes = ResponseBytes::new_basic(resp_type, basic)?;
    Ok(bytes)
}

fn signvalidresponse(bytes: ResponseBytes) -> Result<Vec<u8>, OcspError> {
    let ocsp = OcspResponse::new_success(bytes);
    ocsp.to_der()
}

fn signnonvalidresponse(motif: OcspRespStatus) -> Result<Vec<u8>, OcspError> {
    let ocsp = OcspResponse::new_non_success(motif)?;
    ocsp.to_der()
}

fn createocspresponse(
    cert: CertId,
    cert_status: CertStatus,
    preparedate: Option<u16>,
    thisupdate: Option<GeneralizedTime>,
    nextupdate: Option<GeneralizedTime>,
    extension: Option<Vec<ocsp::common::ocsp::OcspExtI>>,
) -> Result<OneResp, Box<dyn Error>> {
    let thisupdate = thisupdate.unwrap_or(GeneralizedTime::now());
    let mut nextupdate = nextupdate;
    if preparedate.is_some() {
        let now = chrono::offset::Utc::now();
        let elem = now
            .checked_add_days(chrono::Days::new(u64::from(preparedate.unwrap())))
            .unwrap_or(now);
        let new = GeneralizedTime::new(
            elem.year(),
            elem.month(),
            elem.day(),
            elem.hour(),
            elem.minute(),
            elem.second(),
        )?;
        nextupdate = nextupdate.or(Some(new));
    }
    Ok(OneResp {
        cid: cert,
        cert_status,
        this_update: thisupdate,
        next_update: nextupdate,
        one_resp_ext: extension,
    })
}

fn checkcache(state: &State<Arc<Config>>, certname: &str) -> io::Result<Option<Vec<u8>>> {
    let paths = fs::read_dir(&state.cachefolder)?;
    for path in paths {
        let path = path?.path();
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        if filename.starts_with(certname) {
            let elem: Vec<&str> = filename.split(certname).collect();
            if elem.len() != 2 {
                warn!("Invalid filename to check cache: {}", filename);
                continue;
            }
            let datetime = NaiveDateTime::parse_from_str(elem[1], CACHEFORMAT);
            if datetime.is_err() {
                warn!("Cannot parse datetime {}", elem[1]);
                continue;
            }
            let datetime = datetime.unwrap();
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            if datetime.and_utc()
                >= DateTime::from_timestamp_millis(i64::try_from(time).unwrap()).unwrap()
            {
                let text = fs::read(&path)?;
                info!("Got {} from cache", &certname);
                return Ok(Some(text));
            } else {
                match fs::remove_file(&path) {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("Cannot remove file {} because {}", &filename, e)
                    }
                };
            }
        }
    }
    Ok(None)
}

fn addtocache(
    state: &State<Arc<Config>>,
    certnum: &str,
    maxdate: DateTime<FixedOffset>,
    response: &[u8],
) -> io::Result<()> {
    let long = format!(
        "{}/{}{}",
        &state.cachefolder,
        certnum,
        maxdate.format(CACHEFORMAT)
    );
    let path = Path::new(&long);
    fs::write(path, response)
}

#[post("/<_..>", data = "<data>")]
async fn upload2(
    config: &State<Arc<Config>>,
    db: &State<Box<dyn Database>>,
    data: Data<'_>,
    address: SocketAddr,
) -> io::Result<(ContentType, Vec<u8>)> {
    upload(config, db, data, address).await
}

#[get("/<_..>", data = "<data>")]
async fn upload(
    state: &State<Arc<Config>>,
    db: &State<Box<dyn Database>>,
    data: Data<'_>,
    address: SocketAddr,
) -> io::Result<(ContentType, Vec<u8>)> {
    let custom = ContentType::new("application", "ocsp-response");
    let stream = data.open(3.mebibytes());
    let string = stream.into_bytes().await?;
    let vec = string.into_inner();
    let ocsp_request = match OcspRequest::parse(&vec) {
        Ok(r) => {
            trace!("Got a request from {}", address.ip());
            r
        }
        Err(e) => {
            warn!("Unable to parse ocsp request from {}", address.ip());
            debug!("Unable to parse ocsp request, due to {e}.");
            return Ok((
                custom,
                signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
            ));
        }
    };

    match ocsp_request.tbs_request.request_ext.clone().and_then(|p| {
        p.iter()
            .filter_map(|o| match &o.ext {
                ocsp::common::ocsp::OcspExt::Nonce { nonce } => Some(nonce.len()),
                _ => None,
            })
            .next_back()
    }) {
        Some(1..128) | None => (),
        _ => {
            info!("Nonce is invalid on request by {}. Rejected.", address.ip());
            return Ok((
                custom,
                signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
            ));
        }
    }
    // get CertId from request
    let tbs = ocsp_request.tbs_request.request_ext.clone();
    let cid_list = ocsp_request.extract_certid_owned();
    let mut responses: Vec<OneResp> = Vec::new();
    let mut num = String::new();
    let possible = cid_list.len() <= 1 && state.caching;
    let mut extensions = Vec::with_capacity(cid_list.len());
    let mut needthecert = false;
    for cert in cid_list {
        num = match hex::encode(&cert.serial_num).starts_with("0x") {
            true => hex::encode(&cert.serial_num),
            false => format!("{}{}", "0x", hex::encode(&cert.serial_num)),
        };
        if possible {
            let result = checkcache(state, &num);
            if result.is_ok() {
                let result = result.unwrap();
                if let Some(d) = result {
                    return Ok((custom, d));
                }
            }
        }
        let nonce = match state.caching {
            true => None,
            false => {
                let nonce = tbs.clone().map_or_else(
                    || None,
                    |f| {
                        let mut vec: Vec<Vec<u8>> = f
                            .iter()
                            .filter_map(|p| {
                                if let OcspExt::Nonce { nonce: d } = p.ext.clone() {
                                    Some(d)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if vec.len() != 1 {
                            None
                        } else {
                            Some(vec.pop().unwrap())
                        }
                    },
                );
                nonce.map(|d| OcspExtI {
                    id: 0,
                    ext: ocsp::common::ocsp::OcspExt::Nonce { nonce: d.to_vec() },
                })
            }
        };
        if let Some(nonce) = nonce {
            extensions.push(nonce);
        }
        if state.revocextended {
            let revoked = OcspExtI {
                id: 8,
                ext: ocsp::common::ocsp::OcspExt::ExtendedRevocation,
            };
            extensions.push(revoked);
        };

        // Compare that signing certificate is signed by the issuer or the issuer itself https://www.rfc-editor.org/rfc/rfc6960
        let status = match (
            cert.issuer_key_hash == state.issuer_hash.0,
            state.issuer_hash.1 == cert.issuer_key_hash,
            state.issuer_hash.2,
        ) {
            (true, ..) | (.., true, true) => {
                if state.issuer_hash.1 == cert.issuer_key_hash && state.issuer_hash.2 {
                    trace!("Certificate is matching issuer. Providing certificate.");
                    needthecert = true;
                } else {
                    trace!("Certificate is the issuer.");
                }

                match db.check_cert(&num, state.revocextended).await {
                    Ok(status) => status,
                    Err(err) => {
                        error!("Cannot query database: {}", err);
                        return Ok((
                            custom,
                            signnonvalidresponse(OcspRespStatus::TryLater).unwrap(),
                        ));
                    }
                }
            }
            (.., true, false) if !state.issuer_hash.2 => {
                error!(
                    "Certificate used has not OCSP signing extended key usage and cannot sign OCSP!"
                );
                return Ok((
                    custom,
                    signnonvalidresponse(OcspRespStatus::TryLater).unwrap(),
                ));
            }
            _ => {
                warn!(
                    "Certificate {} is not known. Hash is not okay. Got: {}. Expected one of {}/{}",
                    hex::encode(&cert.serial_num),
                    hex::encode(&cert.issuer_key_hash),
                    hex::encode(&state.issuer_hash.0),
                    hex::encode(&state.issuer_hash.1)
                );
                CertStatus::new(CertStatusCode::Unknown, None)
            }
        };

        let resp = createocspresponse(cert, status, Some(state.cachedays), None, None, None);
        if resp.is_err() {
            error!("Error creating OCSP response.");
            debug!(
                "Error creating OCSP response: {}",
                resp.unwrap_err().to_string()
            );
            return Ok((
                custom,
                signnonvalidresponse(OcspRespStatus::TryLater).unwrap(),
            ));
        }
        let resp = resp.unwrap();
        responses.push(resp);
    }
    let certnum = num;
    let extensions = if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    };
    let needthecert: Option<Vec<Bytes>> = if needthecert {
        Some(vec![state.cert.clone()])
    } else {
        None
    };
    let result = signresponse(
        &state.issuer_hash.0,
        &state.rsakey,
        responses,
        extensions,
        needthecert,
    );
    if result.is_err() {
        warn!(
            "Unable to parse ocsp request, due to {:?}.",
            result.unwrap_err()
        );
        return Ok((
            custom,
            signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
        ));
    }
    let result = result.unwrap();
    let response = signvalidresponse(result);
    if response.is_err() {
        error!("Cannot sign the response.");
        return Ok((
            custom,
            signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
        ));
    }
    let response = response.unwrap();
    if possible {
        let date = chrono::Local::now();
        let date = date.checked_add_days(chrono::Days::new(u64::from(state.cachedays)));
        if let Some(date) = date {
            match addtocache(state, &certnum, date.fixed_offset(), &response) {
                Ok(_) => (),
                Err(_) => {
                    warn!("Cannot write to cache");
                }
            }
        }
    }
    info!("Send response for {} to {}", &certnum, address.ip());
    Ok((custom, response))
}

fn getprivatekey<T>(data: T) -> Result<ring::signature::RsaKeyPair, String>
where
    T: AsRef<[u8]>,
{
    if let Ok(key_pair) = ring::signature::RsaKeyPair::from_pkcs8(data.as_ref()) {
        return Ok(key_pair);
    }

    let pem_str = String::from_utf8_lossy(data.as_ref());

    if pem_str.contains("-----BEGIN RSA PRIVATE KEY-----") {
        match convert_rsa_pem_to_pkcs8(&pem_str) {
            Ok(pkcs8_der) => match ring::signature::RsaKeyPair::from_pkcs8(&pkcs8_der) {
                Ok(key_pair) => return Ok(key_pair),
                Err(e) => {
                    return Err(format!(
                        "Error creating KeyPair from converted PKCS#8: {}",
                        e
                    ))
                }
            },
            Err(e) => return Err(format!("RSA PEM conversion error: {}", e)),
        }
    } else if pem_str.contains("-----BEGIN PRIVATE KEY-----") {
        match pem::parse(pem_str.as_bytes()) {
            Ok(pem) => match ring::signature::RsaKeyPair::from_pkcs8(pem.contents()) {
                Ok(key_pair) => return Ok(key_pair),
                Err(e) => return Err(format!("Error creating KeyPair from PEM PKCS#8: {}", e)),
            },
            Err(e) => return Err(format!("PEM parsing error: {}", e)),
        }
    }

    Err("Unsupported key format. Only RSA keys are supported per RFC 6960".to_string())
}

fn convert_rsa_pem_to_pkcs8(
    pem_str: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let pem = pem::parse(pem_str.as_bytes())?;
    let rsa = Rsa::private_key_from_der(pem.contents())?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey.private_key_to_pkcs8()?)
}

fn pem_to_der(pem_str: &str) -> Vec<u8> {
    match parse(pem_str.as_bytes()) {
        Ok(pem) => pem.contents().to_vec(),
        Err(e) => {
            eprintln!("Error parsing PEM: {}", e);
            panic!("Invalid PEM format")
        }
    }
}

#[launch]
fn rocket() -> rocket::Rocket<rocket::Build> {
    let cli = Cli::parse();

    let config_path = &cli.config_path;

    if !Path::new(config_path).exists() {
        eprintln!("Error: Config file not found at: {}", config_path);
        eprintln!("\nUsage information:");
        let mut cli_command = Cli::command();
        if let Err(err) = cli_command.print_help() {
            eprintln!("Could not display help: {}", err);
        }
        std::process::exit(1);
    }

    let config = match Fileconfig::from_config_file(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: Reading config file at {}: {}", config_path, e);
            eprintln!("\nUsage information:");
            let mut cli_command = Cli::command();
            if let Err(err) = cli_command.print_help() {
                eprintln!("Could not display help: {}", err);
            }
            std::process::exit(1);
        }
    };

    let file = fs::read_to_string(&config.itcert).expect("Intermediate cert is not found");
    let file2 = pem_to_der(&file);
    let certpem = x509_parser::pem::parse_x509_pem(file.as_bytes())
        .expect("Invalid intermediate certificate.")
        .1;
    let certpem = certpem
        .parse_x509()
        .expect("Invalid intermediate certificate.");
    let isocsp = certpem
        .extended_key_usage()
        .unwrap()
        .is_some_and(|f| f.value.ocsp_signing || f.value.any);
    if !isocsp {
        eprintln!(
            "Your certificate does not have OCSP signing extended key usage. If it is not the issuer, the application won't sign the response."
        )
    }

    let parsed = certpem
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let issuerkey = match parsed {
        ParsedExtension::AuthorityKeyIdentifier(a) => a.key_identifier.as_ref().unwrap(),
        _ => {
            panic!("Error getting key");
        }
    };

    // For an unknown reason, subject key identifier is not equal to SHA1 hash key so it is used instead.
    let authoritykey = format!("{:x}", issuerkey).to_uppercase().replace(":", "");
    let certpempublickey = &certpem.public_key().subject_public_key.data;
    let sha1key = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, certpempublickey);

    // Read private key and zero it after use
    let mut key = fs::read(&config.itkey).unwrap_or_else(|e| {
        panic!("Error reading key file: {}", e);
    });

    let rsakey = match getprivatekey(&key) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            eprintln!("Error loading private key: {}", e);
            eprintln!("Supported formats: PKCS#8, PEM PKCS#1 (RSA)");
            panic!("Key loading failed");
        }
    };
    key.zeroize();

    // Get HTTP port
    let port = config.port.unwrap_or(DEFAULT_PORT);

    // Get listen IP address
    let listen_ip = config
        .listen_ip
        .clone()
        .unwrap_or_else(|| DEFAULT_LISTEN_IP.to_string());

    // Determine database type and default port
    let db_type = config
        .db_type
        .clone()
        .unwrap_or_else(|| "mysql".to_string());
    let dbport = match db_type.as_str() {
        "postgres" | "postgresql" => config.dbport.or(Some(DEFAULT_POSTGRES_PORT)),
        _ => config.dbport.or(Some(DEFAULT_MYSQL_PORT)),
    };

    // Create configuration
    let config = Arc::new(Config {
        issuer_hash: (
            sha1key.as_ref().to_vec(),
            hex::decode(authoritykey).unwrap(),
            isocsp,
        ),
        revocextended: config.revocextended.unwrap_or(false),
        cert: file2,
        time: config.timeout.unwrap_or(DEFAULT_TIMEOUT),
        rsakey,
        cachefolder: config.cachefolder.clone(),
        caching: config.caching.unwrap_or(true),
        cachedays: config.cachedays,
        dbip: config.dbip.clone(),
        dbuser: config.dbuser.clone(),
        dbpassword: config.dbpassword.clone(),
        dbname: config.dbname.clone(),
        db_type,
        dbport,
        create_table: config.create_table.unwrap_or(false),
        table_name: config.table_name.clone(),
        api_keys: config.api_keys.clone(),
        enable_api: config.enable_api.unwrap_or(false),
        listen_ip,
    });

    // Create database connection and tables if needed
    let db = match database::create_database(config.clone()) {
        Ok(db) => {
            if let Err(e) = db.create_tables_if_needed() {
                eprintln!("Error creating tables: {}", e);
            }
            db
        }
        Err(e) => {
            panic!("Failed to initialize database: {}", e);
        }
    };

    // Create cache folder if it doesn't exist
    let path = Path::new(config.cachefolder.as_str());
    if !path.exists() {
        fs::create_dir_all(path).expect("Cannot create cache folder");
    }

    // Set up Rocket to listen on the configured IP address and port
    let figment = rocket::Config::figment()
        .merge(("port", port))
        .merge(("address", config.listen_ip.clone()));

    // Create rocket instance with routes
    let mut rocket_builder = rocket::build()
        .configure(figment)
        .mount("/", routes![upload])
        .mount("/", routes![upload2])
        .manage(config.clone())
        .manage(db as Box<dyn Database>);

    // Add API routes if enabled
    if config.enable_api {
        info!("API functionality is enabled");
        if config.api_keys.is_none() || config.api_keys.as_ref().unwrap().is_empty() {
            warn!("API is enabled but no API keys are configured - this is insecure");
        }
        rocket_builder = rocket_builder.mount("/api", api::api_routes());
    } else {
        info!("API functionality is disabled");
    }

    rocket_builder
}
