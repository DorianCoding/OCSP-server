use crate::database::Database;
use crate::r#struct::{ApiKey, CertificateRequest, CertificateResponse, RevocationRequest};
use chrono::Utc;
use log::{error, info, warn};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::json::Json;
use rocket::{get, post, routes, State};
use std::sync::Arc;

pub fn api_routes() -> Vec<rocket::Route> {
    routes![
        health_check,
        add_certificate,
        revoke_certificate,
        get_certificate_status,
        list_certificates
    ]
}

/// API key authentication guard for secure endpoints
#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Get API key from header
        let api_key = request.headers().get_one("X-API-Key");

        match api_key {
            Some(key) => {
                let config = request.rocket().state::<Arc<crate::r#struct::Config>>();

                match config {
                    Some(config) => {
                        if let Some(valid_keys) = &config.api_keys {
                            if valid_keys.contains(&key.to_string()) {
                                Outcome::Success(ApiKey(key.to_string()))
                            } else {
                                warn!("Invalid API key attempted: {}", key);
                                Outcome::Error((Status::Unauthorized, ()))
                            }
                        } else {
                            // If no API keys are configured, reject all requests
                            warn!("API keys not configured but API endpoint accessed");
                            Outcome::Error((Status::Unauthorized, ()))
                        }
                    }
                    None => Outcome::Error((Status::InternalServerError, ())),
                }
            }
            None => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

#[get("/health")]
fn health_check() -> &'static str {
    "OK"
}

/// Add a new certificate to the database
#[post("/certificates", data = "<cert_request>")]
async fn add_certificate(
    _api_key: ApiKey,
    cert_request: Json<CertificateRequest>,
    db: &State<Box<dyn Database>>,
) -> Result<Json<CertificateResponse>, Status> {
    let cert = cert_request.into_inner();

    // Validate certificate number format (should start with 0x)
    if !cert.cert_num.starts_with("0x") {
        return Err(Status::BadRequest);
    }

    match db.add_certificate(&cert.cert_num).await {
        Ok(_) => {
            info!("Certificate added successfully: {}", cert.cert_num);
            Ok(Json(CertificateResponse {
                cert_num: cert.cert_num,
                status: "Valid".to_string(),
                message: "Certificate added successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to add certificate: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

/// Revoke a certificate
#[post("/certificates/revoke", data = "<revoke_request>")]
async fn revoke_certificate(
    _api_key: ApiKey,
    revoke_request: Json<RevocationRequest>,
    db: &State<Box<dyn Database>>,
) -> Result<Json<CertificateResponse>, Status> {
    let request = revoke_request.into_inner();

    // Validate certificate number format
    if !request.cert_num.starts_with("0x") {
        return Err(Status::BadRequest);
    }

    // Validate revocation reason
    let valid_reasons = [
        "unspecified",
        "key_compromise",
        "ca_compromise",
        "affiliation_changed",
        "superseded",
        "cessation_of_operation",
        "certificate_hold",
        "privilege_withdrawn",
        "aa_compromise",
    ];

    if !valid_reasons.contains(&request.reason.as_str()) {
        return Err(Status::BadRequest);
    }

    // Use current time if not provided
    let revocation_time = request
        .revocation_time
        .unwrap_or_else(|| Utc::now().naive_utc());

    match db
        .revoke_certificate(&request.cert_num, revocation_time, &request.reason)
        .await
    {
        Ok(_) => {
            info!("Certificate revoked successfully: {}", request.cert_num);
            Ok(Json(CertificateResponse {
                cert_num: request.cert_num,
                status: "Revoked".to_string(),
                message: "Certificate revoked successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to revoke certificate: {}", e);
            Err(Status::InternalServerError)
        }
    }
}

/// Get the status of a specific certificate
#[get("/certificates/<cert_num>")]
async fn get_certificate_status(
    _api_key: ApiKey,
    cert_num: String,
    db: &State<Box<dyn Database>>,
) -> Result<Json<CertificateResponse>, Status> {
    let cert_num = if !cert_num.starts_with("0x") {
        format!("0x{}", cert_num)
    } else {
        cert_num
    };

    match db.get_certificate_status(&cert_num).await {
        Ok(cert_info) => Ok(Json(CertificateResponse {
            cert_num: cert_num.clone(),
            status: cert_info.status.clone(),
            message: format!("Certificate status retrieved: {}", cert_info.status),
        })),
        Err(_) => Err(Status::NotFound),
    }
}

/// List all certificates or filter by status
#[get("/certificates?<status>")]
async fn list_certificates(
    _api_key: ApiKey,
    status: Option<String>,
    db: &State<Box<dyn Database>>,
) -> Result<Json<Vec<CertificateResponse>>, Status> {
    let liststatus = ["Valid","revoked","All"];
    let filtered_status = match status {
        Some(d) if liststatus.iter().any(|p| *p == d.as_str()) => {
            if d == "All" {
                Some(d)
            } else {
                None
            }
        },
        _ => {
            return Err(Status::BadRequest);
        }
    };

    match db.list_certificates(filtered_status).await {
        Ok(certs) => {
            let response = certs
                .into_iter()
                .map(|cert| CertificateResponse {
                    cert_num: cert.cert_num,
                    status: cert.status,
                    message: String::new(),
                })
                .collect();

            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to list certificates: {}", e);
            Err(Status::InternalServerError)
        }
    }
}
