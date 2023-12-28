#[macro_use]
extern crate rocket;
use chrono::{self, Timelike};
use chrono::{DateTime, Datelike, FixedOffset, NaiveDateTime};
use config_file::FromConfigFile;
use serde::Deserialize;
use hex;
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
use openssl::{hash, pkey, sign, x509};
use rocket::http::ContentType;
use rocket::State;
use rocket::{data::ToByteUnit, Data};
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{exit, ExitCode};
use std::time::Duration;
use zeroize::Zeroize;
const CACHEFORMAT: &str = "%Y-%m-%d-%H-%M-%S";
// In a real application, this would likely be more complex.
#[derive(Debug)]
struct Config {
    issuer_hash: Vec<u8>,
    issuer_name_hash: u32,
    rsakey: pkey::PKey<pkey::Private>,
    cachedays: u16,
    dbip: String,
    dbuser: String,
    dbpassword: String,
    dbname: String,
    cachefolder: String,
}
#[derive(Deserialize)]
struct Fileconfig {
    cachedays: u16,
    dbip: String,
    port: u32,
    dbuser: String,
    dbpassword: String,
    dbname: String,
    cachefolder: String,
    itkey: String,
    itcert: String
}
unsafe impl Send for Config {}
unsafe impl Sync for Config {}
#[post("/<_..>", data = "<data>")]
async fn upload2<'a>(config: &State<Config>, data: Data<'a>) -> io::Result<(ContentType, Vec<u8>)> {
    upload(config, data).await
}
fn signresponse(
    issuer_hash: &[u8],
    private_key: pkey::PKey<pkey::Private>,
    response: Vec<OneResp>,
) -> Result<ResponseBytes, Box<dyn std::error::Error>> {
    let id = ResponderId::new_key_hash(&issuer_hash); // responding by id
    let produce = GeneralizedTime::now();
    let data = ResponseData::new(id, produce, response, None);
    let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT)?;
    let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &private_key)?;
    let tosign = &data.to_der()?;
    signer.update(tosign)?;
    let signature = signer.sign_to_vec()?;
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
#[derive(Debug, PartialEq, Clone)]
struct Certinfo {
    status: String,
    revocation_time: Option<mysql::Value>,
    revocation_reason: Option<String>,
    cert: String,
}
fn checkcert(config: &State<Config>, certnum: &str) -> Result<OcspCertStatus, mysql::Error> {
    // Let's select payments from database. Type inference should do the trick here.
    let opts = OptsBuilder::new()
        .user(Some(config.dbuser.as_str()))
        //        .prefer_socket(true)
        //        .socket(Some("/run/mysqld/mysqld.sock"))
        .ip_or_hostname(Some(config.dbip.as_str()))
        .read_timeout(Some(Duration::new(5, 0)))
        .db_name(Some(config.dbname.as_str()))
        .pass(Some(config.dbpassword.as_str()));
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
    if selected_payments.len() == 0 {
        warn!("Entry not found for cert {}", certnum);
        Ok(OcspCertStatus::new(CertStatusCode::Unknown, None))
    } else {
        let selected_payments = selected_payments[0].clone();
        debug!(
            "Entry found for cert {}, status {}",
            certnum, selected_payments.status
        );
        if selected_payments.status == "Revoked" {
            let time = GeneralizedTime::now();
            let date = &selected_payments.revocation_time;
            let timenew = match date {
                Some(mysql::Value::Date(year, month, day, hour, min, sec, _ms)) => {
                    GeneralizedTime::new(
                        i32::from(year.clone()),
                        u32::from(month.clone()),
                        u32::from(day.clone()),
                        u32::from(hour.clone()),
                        u32::from(min.clone()),
                        u32::from(sec.clone()),
                    )
                }
                _ => Ok(time),
            };
            let time = timenew.unwrap_or(time);
            let motif = selected_payments.revocation_reason.unwrap_or_default();
            let motif = motif.as_str();
            let motif: CrlReason = match motif {
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
    preparedate: bool,
    thisupdate: Option<GeneralizedTime>,
    nextupdate: Option<GeneralizedTime>,
    extension: Option<Vec<ocsp::common::ocsp::OcspExtI>>,
) -> Result<OneResp, Box<dyn Error>> {
    let thisupdate = thisupdate.unwrap_or(GeneralizedTime::now());
    let mut nextupdate = nextupdate;
    if preparedate {
        let now = chrono::offset::Utc::now();
        let elem = now.checked_add_days(chrono::Days::new(3)).unwrap_or(now);
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
        cert_status: cert_status,
        this_update: thisupdate,
        next_update: nextupdate,
        one_resp_ext: extension,
    })
}
fn checkcache(state: &State<Config>, certname: String) -> io::Result<Option<Vec<u8>>> {
    let paths = fs::read_dir(&state.cachefolder)?;
    for path in paths {
        let path = path?.path();
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        if filename.starts_with(&certname) {
            let elem: Vec<&str> = filename.split(&certname).collect();
            if elem.len() != 2 {
                continue;
            }
            let datetime = NaiveDateTime::parse_from_str(elem[1], CACHEFORMAT);
            if datetime.is_err() {
                continue;
            }
            let datetime = datetime.unwrap();
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            if datetime
                >= chrono::NaiveDateTime::from_timestamp_millis(i64::try_from(time).unwrap())
                    .unwrap()
            {
                let text = fs::read(path)?;
                warn!("Got {} from cache", &certname);
                return Ok(Some(text));
            }
        }
    }
    Ok(None)
}
fn addtocache(state: &State<Config>, certnum: &str, maxdate: DateTime<FixedOffset>, response: &[u8]) -> io::Result<()> {
    let long = format!("{}/{}{}", &state.cachefolder, certnum, maxdate.format(CACHEFORMAT));
    let path = Path::new(&long);
    fs::write(path, response)
}
#[get("/<_..>", data = "<data>")]
async fn upload<'a>(state: &State<Config>, data: Data<'a>) -> io::Result<(ContentType, Vec<u8>)> {
    let custom = ContentType::new("application", "ocsp-response");
    let stream = data.open(3.mebibytes());
    let string = stream.into_bytes().await?;
    let vec = string.into_inner();
    let ocsp_request = match OcspRequest::parse(&vec) {
        Ok(r) => r,
        Err(e) => {
            warn!("Unable to parse ocsp request, due to {e}.");
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
    let possible = if cid_list.len() > 1 { false } else { true };
    for cert in cid_list {
        let mut certnum: String = hex::encode(&cert.serial_num);
        if !certnum.starts_with("0x") {
            certnum.insert_str(0, "0x");
        }
        num = certnum.clone();
        if possible {
            let result = checkcache(&state,certnum.clone());
            if result.is_ok() {
                let result = result.unwrap();
                if result.is_some() {
                    return Ok((custom, result.unwrap()));
                }
            }
        }
        let mut status = CertStatus::new(CertStatusCode::Unknown, None);
        /* let mut opensslshorthash: [u8;4] = [0;4];
        opensslshorthash.clone_from_slice(&cert.issuer_name_hash[..4]);
        let opensslshorthash=u32::from_le_bytes(opensslshorthash); TODO: Implement */
        //if  opensslshorthash != state.issuer_name_hash
        if cert.issuer_key_hash != state.issuer_hash {
            warn!("Certificate {} is not known", hex::encode(&cert.serial_num));
        } else {
            status = match checkcert(&state, &certnum.clone()) {
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
        let resp = createocspresponse(cert, status, true, None, None, None);
        if resp.is_err() {
            warn!(
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
    let result = signresponse(&state.issuer_hash, state.rsakey.clone(), responses);
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
            match addtocache(&state, &num, date.unwrap().fixed_offset(), &response) {
                Ok(_) => (),
                Err(_) => {
                    warn!("Cannot write cache");
                }
            }
        }
    }
    Ok((custom, response))
}
fn getprivatekey(data: &str) -> Result<pkey::PKey<pkey::Private>, openssl::error::ErrorStack> {
    pkey::PKey::private_key_from_pem(data.as_bytes())
}
#[launch]
fn rocket() -> _ {
    let config = Fileconfig::from_config_file("config.toml").unwrap();
    let file = fs::read_to_string(config.itcert).unwrap();
    let certpem = x509::X509::from_pem(file.as_bytes()).unwrap();
    let issuer_hash = certpem.subject_key_id().unwrap().as_slice().to_vec();
    let issuer_name_hash = certpem.subject_name_hash();
    let mut key = fs::read_to_string(config.itkey).unwrap();
    let rsakey = getprivatekey(&key).unwrap();
    key.zeroize();
    let port: u8 = u8::try_from(config.port).unwrap();
    let config = Config {
        issuer_hash,
        issuer_name_hash,
        rsakey,
        cachefolder: config.cachefolder,
        cachedays: config.cachedays,
        dbip: config.dbip,
        dbuser: config.dbuser,
        dbpassword: config.dbpassword,
        dbname: config.dbname
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
