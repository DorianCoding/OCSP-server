use ocsp::{
    common::asn1::{CertId, GeneralizedTime, Oid},
    oid::{ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT, OCSP_RESPONSE_BASIC_DOT},
    request::OcspRequest,
    response::{
        BasicResponse, CertStatus as OcspCertStatus, CertStatus, CertStatusCode, CrlReason,
        OcspRespStatus, OcspResponse, OneResp, ResponderId, ResponseBytes, ResponseData,
        RevokedInfo,
    },
};
use chrono;
use std::{env, fs};
pub fn certdate(days: u8) -> GeneralizedTime {
        let mut now = chrono::offset::Utc::now();
        let elem = now.checked_add_days(days);
        if elem.is_none() {
            panic!("Invalid data");
        }
        now=elem.unwrap();
        GeneralizedTime::new(now.year(),now.month(),now.day(),now.hour(),now.minute(),now.second()).unwrap()
}
fn sendbadinput() {}
fn response() {
    let key = fs::read("privatekey.pem").unwrap();
    let id = ResponderId::new_key_hash(&key); // responding by id
    // year, month, day, hour(24), minute, second
    let produce = certdate(2);
    // you can extract cid from request
    let oid = Oid::new_from_dot("1.3.14.3.2.26").unwrap();
    let name = vec![
        0x69, 0x4d, 0x18, 0xa9, 0xbe, 0x42, 0xf7, 0x80, 0x26, 0x14, 0xd4, 0x84, 0x4f, 0x23, 0x60,
        0x14, 0x78, 0xb7, 0x88, 0x20,
    ];
    let key = vec![
        0x39, 0x7b, 0xe0, 0x02, 0xa2, 0xf5, 0x71, 0xfd, 0x80, 0xdc, 0xeb, 0x52, 0xa1, 0x7a, 0x7f,
        0x8b, 0x63, 0x2b, 0xe7, 0x55,
    ];
    let sn = vec![0x41, 0x30, 0x09, 0x83, 0x33, 0x1f, 0x9d, 0x4f];
    let certid = CertId::new(oid.clone(), &name, &key, &sn);

    let good = OcspCertStatus::new(CertStatusCode::Good, None);
    let gt = GeneralizedTime::now();

    let one = OneResp {
        cid: certid.clone(),
        cert_status: good,
        this_update: gt,
        next_update: None,
        one_resp_ext: None,
    };

    let sn2 = vec![0x63, 0x78, 0xe5, 0x1d, 0x44, 0x8f, 0xf4, 0x6d];
    let certid2 = CertId::new(oid, &name, &key, &sn2);
    let rev_t = GeneralizedTime::new(2020, 11, 30, 1, 48, 25).unwrap();
    let rev_info = RevokedInfo::new(rev_t, Some(CrlReason::OcspRevokeUnspecified));
    let revoke = OcspCertStatus::new(CertStatusCode::Revoked, Some(rev_info));
    let two = OneResp {
        cid: certid2,
        cert_status: revoke,
        this_update: gt,
        next_update: None,
        one_resp_ext: None,
    };

    let list = [one, two].to_vec();
    let data = ResponseData::new(id, produce, list, None);
    // other signatures also supported, see oid
    // equivalent to
    // let oid = Oid::new_from_dot("1.2.840.113549.1.1.5").await.unwrap();
    let oid = Oid::new_from_dot(ALGO_SHA256_WITH_RSA_ENCRYPTION_DOT).unwrap();

    let some_signing_machine = || async { vec![0x00] };
    let sign = some_signing_machine().await; //example signature

    let basic = BasicResponse::new(data, oid, sign, None);
    // equivalent to
    // let resp_type = Oid::new_from_dot("1.3.6.1.5.5.7.48.1.1").await.unwrap();
    let resp_type = Oid::new_from_dot(OCSP_RESPONSE_BASIC_DOT).unwrap();
    let bytes = ResponseBytes::new_basic(resp_type, basic).unwrap();
    let ocsp = OcspResponse::new_success(bytes);
    let resp_binary = ocsp.to_der().unwrap();

    // return resp_binary as response body
}
fn main() {
    let args:Vec<String> = env::args().collect();
    if args.len() != 1 {
        sendbadinput();
    }
    let result = fs::read(args[0]);
    if result.is_err() {
        sendbadinput();
    }
    let result = result.unwrap();
    let ocsp_request = OcspRequest::parse(&result);
    // get CertId from request
    if ocsp_request.is_err() {
        sendbadinput();
    }
    let ocsp_request = ocsp_request.unwrap();
    let cid_list = ocsp_request.extract_certid_owned();
    response();
}
