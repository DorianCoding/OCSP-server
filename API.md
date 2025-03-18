# Certificate Management API for OCSP Server

This API allows you to add, revoke, and query certificates in the database used by the OCSP server.

## Configuration

To enable the API, add the following parameters to your `config.toml` file:

```toml
# API Configuration
enable_api = true # Enable the API
api_keys = ["your-secure-api-key"] # List of valid API keys
```

## Generating Secure API Keys

API keys should be random, hard to guess, and unique. Here are different methods to generate secure API keys:

### Using OpenSSL

The simplest way to generate a secure API key is using OpenSSL:

```bash
# Generate a 32-byte random hexadecimal string
openssl rand -hex 32
```

Example output: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6`

After generating an API key, add it to the `api_keys` array in your `config.toml` file.

## Authentication

All API requests must include an `X-API-Key` header with a valid API key.

## Finding Certificate Numbers

To use this API, you need the certificate number in the correct format (with `0x` prefix and lowercase hexadecimal digits). You can extract a certificate's serial number and format it properly using this command:

```bash
openssl x509 -in your_certificate.pem -serial -noout | awk -F= '{print "0x" tolower($2)}'
```

This will output the certificate number in the exact format required by the API endpoints (e.g., `0x3b6ea97e1bf7699397e2109846e4f356be982542`).

## Endpoints

### Health Check
```
GET /api/health
```
Returns "OK" if the service is available.

### Add a Certificate
```
POST /api/certificates
```

**Request Body:**
```json
{
  "cert_num": "0x123456789ABCDEF"
}
```

**Example Response:**
```json
{
  "cert_num": "0x123456789ABCDEF",
  "status": "Valid",
  "message": "Certificate added successfully"
}
```

### Revoke a Certificate
```
POST /api/certificates/revoke
```

**Request Body:**
```json
{
  "cert_num": "0x123456789ABCDEF",
  "reason": "key_compromise",
  "revocation_time": "2025-03-18T12:00:00" // Optional, uses the current time if not provided
}
```

Valid revocation reasons are:
- `unspecified`
- `key_compromise`
- `ca_compromise`
- `affiliation_changed`
- `superseded`
- `cessation_of_operation`
- `certificate_hold`
- `privilege_withdrawn`
- `aa_compromise`

**Example Response:**
```json
{
  "cert_num": "0x123456789ABCDEF",
  "status": "Revoked",
  "message": "Certificate revoked successfully"
}
```

### Get a Certificate's Status
```
GET /api/certificates/{cert_num}
```

**Example Response:**
```json
{
  "cert_num": "0x123456789ABCDEF",
  "status": "Valid",
  "message": "Certificate status retrieved: Valid"
}
```

### List All Certificates
```
GET /api/certificates
```

Optional parameters:
- `status`: Filter by status (`Valid`, `Revoked`, or `all`)
  - If no `status` parameter is provided or `status=all` is used, all certificates will be returned
  - Use `status=Valid` to return only valid certificates
  - Use `status=Revoked` to return only revoked certificates

**Example Response:**
```json
[
  {
    "cert_num": "0x123456789ABCDEF",
    "status": "Valid",
    "message": ""
  },
  {
    "cert_num": "0x987654321FEDCBA",
    "status": "Revoked",
    "message": ""
  }
]
```

## Usage Examples with cURL

### Add a Certificate
```bash
curl -X POST http://localhost:9000/api/certificates \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"cert_num": "0x123456789ABCDEF"}'
```

### Revoke a Certificate
```bash
curl -X POST http://localhost:9000/api/certificates/revoke \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"cert_num": "0x123456789ABCDEF", "reason": "key_compromise"}'
```

### Get a Certificate's Status
```bash
curl -X GET http://localhost:9000/api/certificates/0x123456789ABCDEF \
  -H "X-API-Key: your-api-key"
```

### List All Valid Certificates
```bash
curl -X GET "http://localhost:9000/api/certificates?status=Valid" \
  -H "X-API-Key: your-api-key"
```

### List All Certificates (Explicitly)
```bash
curl -X GET "http://localhost:9000/api/certificates?status=all" \
  -H "X-API-Key: your-api-key"
```
