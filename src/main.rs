#[macro_use]
extern crate rocket;
use chrono::{self, NaiveDateTime, Timelike};
use chrono::{DateTime, Datelike, FixedOffset};
use config_file::FromConfigFile;
use mysql::prelude::Queryable;
use mysql::*;
use ocsp::request::OcspRequest;
use ocsp::{
    common::asn1::{CertId, GeneralizedTime, Oid},
    err::OcspError,
    oid::{ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT, OCSP_RESPONSE_BASIC_DOT},
    response::{
        BasicResponse, CertStatus as OcspCertStatus, CertStatus, CertStatusCode, CrlReason,
        OcspRespStatus, OcspResponse, OneResp, ResponderId, ResponseBytes, ResponseData,
        RevokedInfo,
    },
};
use ring::{rand, signature};
use rocket::http::ContentType;
use rocket::State;
use rocket::{data::ToByteUnit, Data};
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;
use x509_parser::prelude::ParsedExtension;
use zeroize::Zeroize;
const CACHEFORMAT: &str = "%Y-%m-%d-%H-%M-%S";
// In a real application, this would likely be more complex.
#[derive(Debug)]
struct Config {
    issuer_hash: Vec<u8>,
    //issuer_name_hash: u32,
    rsakey: ring::signature::RsaKeyPair,
    cachedays: u16,
    dbip: Option<String>,
    dbuser: String,
    dbpassword: String,
    dbname: String,
    cachefolder: String,
}
impl Drop for Config {
    fn drop(&mut self) {
        self.dbip.zeroize();
        self.dbuser.zeroize();
        self.dbpassword.zeroize();
        self.dbname.zeroize();
    }
}
#[derive(Deserialize)]
struct Fileconfig {
    cachedays: u16,
    dbip: Option<String>,
    port: u32,
    dbuser: String,
    dbpassword: String,
    dbname: String,
    cachefolder: String,
    itkey: String,
    itcert: String,
    realhash: Option<String>,
}
#[derive(Debug, PartialEq, Clone)]
struct Certinfo {
    status: String,
    revocation_time: Option<mysql::Value>,
    revocation_reason: Option<String>,
    cert: String,
}
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
fn signresponse(
    issuer_hash: &[u8],
    private_key: &ring::rsa::KeyPair,
    response: Vec<OneResp>,
) -> Result<ResponseBytes, Box<dyn std::error::Error>> {
    let id = ResponderId::new_key_hash(issuer_hash); // responding by id
    let produce = GeneralizedTime::now();
    let data = ResponseData::new(id, produce, response, None);
    let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT)?;
    let rng = rand::SystemRandom::new();
    let tosign = &data.to_der()?;
    let mut signature = vec![0u8; private_key.public().modulus_len()];
    private_key
        .sign(&signature::RSA_PKCS1_SHA256, &rng, tosign, &mut signature)
        .unwrap();
    assert_ne!(&signature, tosign);
    let basic = BasicResponse::new(data, oid, signature, None);
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
fn checkcert(config: &State<Config>, certnum: &str) -> Result<OcspCertStatus, mysql::Error> {
    // Let's select payments from database. Type inference should do the trick here.
    let opts = OptsBuilder::new()
        .user(Some(config.dbuser.as_str()))
        .read_timeout(Some(Duration::new(5, 0)))
        .db_name(Some(config.dbname.as_str()))
        .pass(Some(config.dbpassword.as_str()));
    let opts = match &config.dbip {
        Some(string) => opts.ip_or_hostname(Some(string)),
        None => opts
            .prefer_socket(true)
            .socket(Some("/run/mysqld/mysqld.sock")),
    };
    let mut conn = Conn::new(opts)?;
    let selected_payments = conn.exec_map(
        "SELECT status, revocation_time, revocation_reason, cert FROM list_certs WHERE cert_num=?",
        (String::from(certnum).into_bytes(),),
        |(status, revocation_time, revocation_reason, cert)| Certinfo {
            status,
            revocation_time,
            revocation_reason,
            cert,
        },
    )?;
    if selected_payments.is_empty() {
        warn!("Entry not found for cert {}", certnum);
        Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
    } else {
        let statut = selected_payments[0].clone();
        debug!("Entry found for cert {}, status {}", certnum, statut.status);
        if statut.status == "Revoked" {
            let time = GeneralizedTime::now();
            let date = &statut.revocation_time;
            let timenew = match date {
                Some(mysql::Value::Date(year, month, day, hour, min, sec, _ms)) => {
                    GeneralizedTime::new(
                        i32::from(*year),
                        u32::from(*month),
                        u32::from(*day),
                        u32::from(*hour),
                        u32::from(*min),
                        u32::from(*sec),
                    )
                }
                _ => Ok(time),
            };
            let time = timenew.unwrap_or(time);
            let motif = statut.revocation_reason.unwrap_or_default();
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
fn checkcache(state: &State<Config>, certname: &str) -> io::Result<Option<Vec<u8>>> {
    let paths = fs::read_dir(&state.cachefolder)?;
    for path in paths {
        let path = path?.path();
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        if filename.starts_with(certname) {
            let elem: Vec<&str> = filename.split(&certname).collect();
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
    state: &State<Config>,
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
async fn upload2<'a>(
    config: &State<Config>,
    data: Data<'a>,
    address: SocketAddr,
) -> io::Result<(ContentType, Vec<u8>)> {
    upload(config, data, address).await
}
#[get("/<_..>", data = "<data>")]
async fn upload<'a>(
    state: &State<Config>,
    data: Data<'a>,
    address: SocketAddr,
) -> io::Result<(ContentType, Vec<u8>)> {
    let custom = ContentType::new("application", "ocsp-response");
    let stream = data.open(3.mebibytes());
    let string = stream.into_bytes().await?;
    let vec = string.into_inner();
    let ocsp_request = match OcspRequest::parse(&vec) {
        Ok(r) => r,
        Err(e) => {
            warn!("Unable to parse ocsp request from {}", address.ip());
            debug!("Unable to parse ocsp request, due to {e}.");
            return Ok((
                custom,
                signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
            ));
        }
    };
    // get CertId from request
    let cid_list = ocsp_request.extract_certid_owned();
    let mut responses: Vec<OneResp> = Vec::new();
    let mut num = String::new();
    let possible = cid_list.len() <= 1;
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
        let mut status = CertStatus::new(CertStatusCode::Unknown, None);
        /* let mut opensslshorthash: [u8;4] = [0;4];
        opensslshorthash.clone_from_slice(&cert.issuer_name_hash[..4]);
        let opensslshorthash=u32::from_le_bytes(opensslshorthash); TODO: Implement */
        //if  opensslshorthash != state.issuer_name_hash
        if cert.issuer_key_hash != state.issuer_hash {
            warn!(
                "Certificate {} is not known. Hash is not okay. Expected: {}. Got {}",
                hex::encode(&cert.serial_num),
                hex::encode(&cert.issuer_key_hash),
                hex::encode(&state.issuer_hash)
            );
        } else {
            status = match checkcert(state, &num) {
                Ok(status) => status,
                Err(default) => {
                    error!("Cannot connect to database: {}", default.to_string());
                    return Ok((
                        custom,
                        signnonvalidresponse(OcspRespStatus::TryLater).unwrap(),
                    ));
                }
            };
        }
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
    let result = signresponse(&state.issuer_hash, &state.rsakey, responses);
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
        return Ok((
            custom,
            signnonvalidresponse(OcspRespStatus::MalformedReq).unwrap(),
        ));
    }
    let response = response.unwrap();
    if possible {
        let date = chrono::Local::now();
        let date = date.checked_add_days(chrono::Days::new(state.cachedays.into())); //TODO: Implement
        if date.is_some() {
            match addtocache(state, &certnum, date.unwrap().fixed_offset(), &response) {
                Ok(_) => (),
                Err(_) => {
                    warn!("Cannot write to cache");
                }
            }
        }
    }
    info!("Send response for certificate {}", &certnum);
    Ok((custom, response))
}
fn getprivatekey<T>(data: T) -> Result<ring::rsa::KeyPair, ring::error::KeyRejected>
where
    T: AsRef<[u8]>,
{
    ring::rsa::KeyPair::from_pkcs8(data.as_ref())
}
#[launch]
fn rocket() -> _ {
    let config = Fileconfig::from_config_file("config.toml").unwrap();
    let file = fs::read_to_string(config.itcert).unwrap();
    let certpem = x509_parser::pem::parse_x509_pem(file.as_bytes()).unwrap().1;
    let certpem = certpem.parse_x509().unwrap();
    let issuerkey = match config.realhash {
        Some(hex) => {
            println!("Getting a different key to check issuer. If you sign with issuer, delete realhash from config file");
            hex.to_uppercase().replace(":", "")
        },
        None => {
            let parsed = certpem
                .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
                .unwrap()
                .unwrap()
                .parsed_extension();
            let issuerkey = match parsed {
                ParsedExtension::SubjectKeyIdentifier(a) => a,
                _ => {
                    panic!("Error getting key");
                }
            };
            format!("{:x}", issuerkey).to_uppercase().replace(":", "")
        }
    };
    /* let certpempublickey = &certpem.public_key().subject_public_key.data;
    let sha1key = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, certpempublickey); */
    //let issuer_name_hash = certpem.subject_name_hash();
    let mut key = fs::read(config.itkey).unwrap();
    let rsakey = getprivatekey(&key).unwrap();
    key.zeroize();
    let port: u16 = u16::try_from(config.port).unwrap();
    let config = Config {
        issuer_hash: hex::decode(issuerkey).unwrap(),
        //issuer_name_hash,
        rsakey,
        cachefolder: config.cachefolder,
        cachedays: config.cachedays,
        dbip: config.dbip,
        dbuser: config.dbuser,
        dbpassword: config.dbpassword,
        dbname: config.dbname,
    };
    let path = Path::new(config.cachefolder.as_str());
    if !path.exists() {
        fs::create_dir_all(path).unwrap();
    }
    rocket::build()
        .configure(rocket::Config::figment().merge(("port", port)))
        .mount("/", routes![upload])
        .mount("/", routes![upload2])
        .manage(config)
}
