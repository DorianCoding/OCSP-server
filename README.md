#  OCSP Server

OCSP Server is the Rust implementation of the [python version](https://github.com/DorianCoding/OCSP_MySql).

![GitHub License](https://img.shields.io/github/license/DorianCoding/OCSP_server)
[![Github stars](https://img.shields.io/github/stars/DorianCoding/OCSP_server.svg)](https://github.com/DorianCoding/OCSP_server/stargazers)
# OCSP server connected to MySql Database
This software implements a OCSP responder in Rust, fetching certificate status in a Mysql Database. Unlike the Python implementation, it **does implement its own TCP listener** on port 9000.
## Requirements
- A CA certificate (self-signed allowed) and an intermediate CA that will sign leaf certificates.
- A Mysql database containing all certificates (check below)
## What is done
- Extract OCSP requests, verify it is a signed certificate by the CA, check in the database if it is good or revoked and sign the response. It also caches answers for the duration of the signed response.
- Create a specific user for this task to ensure protection for intermediate certificate, as the private key is required.
## What is not done
- Only leaf certificates will be signed as valid, not the intermediate one.
- Security over the TCP socket
## How to implement?
### Binaries
1) Clone the repo `git clone https://github.com/DorianCoding/OCSP_MySql.git`
2) Extract binaries for your architecture and execute it in the background.
## Compile from source
1) Clone the repo `git clone https://github.com/DorianCoding/OCSP_MySql.git`
2) Type `cargo run` and enjoy 👍
## MySql tables
This script requires a table like this :
```
CREATE TABLE `list_certs` (
  `cert_num` varchar(50) NOT NULL,
  `revocation_time` datetime DEFAULT NULL,
  `revocation_reason` enum('unspecified','key_compromise','ca_compromise','affiliation_changed','superseded','cessation_of_operation','certificate_hold','privilege_withdrawn','aa_compromise') DEFAULT NULL,
  `cert` blob NOT NULL,
  `status` enum('Valid','Revoked') NOT NULL DEFAULT 'Valid',
  PRIMARY KEY (`cert_num`),
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
```
- The certificate number **must be unique** and stars with 0x (like a hex number). Cert must contain the certificate.
## Input
This software requires an OCSP request in binary form from the socket client. A request look like this (**in base64 format**), the binary form (DER format) is not human-readable but is the one needed :
```
MHoweDBRME8wTTAJBgUrDgMCGgUABBRGf2x685RgF9qF4azpunF6LM75OQQUwX3C7a+au9Af8tx/
tcfCxFkwR68CFAlOMV+mrbm8PqIFZKeyLubrqlXgoiMwITAfBgkrBgEFBQcwAQIEEgQQkcDcDZCP
zGR57CNCnt6eKg==
```
You can use `openssl ocsp -reqin file -req_text` to verify the format, which will give you something like this :
```
OCSP Request Data:
    Version: 1 (0x0)
    Requestor List:
        Certificate ID:
          Hash Algorithm: sha1
          Issuer Name Hash: 467F6C7AF3946017DA85E1ACE9BA717A2CCEF939
          Issuer Key Hash: C17DC2EDAF9ABBD01FF2DC7FB5C7C2C4593047AF
          Serial Number: 094E315FA6ADB9BC3EA20564A7B22EE6EBAA55E0
    Request Extensions:
        OCSP Nonce:
            041091C0DC0D908FCC6479EC23429EDE9E2A
```
## Output
The software will give a binary file which is the OCSP response in DER format, just as before, the base64 form :
```
MIIB1woBAKCCAdAwggHMBgkrBgEFBQcwAQEEggG9MIIBuTCBoqIWBBTBfcLtr5q70B/y3H+1x8LE
WTBHrxgPMjAyMjEyMjkxMzE5MDlaMHcwdTBNMAkGBSsOAwIaBQAEFEZ/bHrzlGAX2oXhrOm6cXos
zvk5BBTBfcLtr5q70B/y3H+1x8LEWTBHrwIUCU4xX6atubw+ogVkp7Iu5uuqVeCAABgPMjAyMjEy
MjkxMzE5MDlaoBEYDzIwMjIxMjMwMTMxOTA4WjANBgkqhkiG9w0BAQsFAAOCAQEAkIg1jf1Y5gm2
FB0eAdgfP5/h0CddJBYyD0p8SvwXdTTU+Uee+7zUhTwNzq3omosSLMgJ2yEjEv/vai4XgvCeJ+uL
vhMZADzgmifNw/58o94F7RbY9t9XoKhioS9tN0QT/y7Gzyz16vD+vYYqkW8Pvb6ueRL5A3QUARUz
eUZoU24omksxF3smVbCzM8czBAre5ydejKDS6GjnMcTZqg+GggVYJMS7ZocHVbwVRv75xFo+M/7P
cg78TNJ+KtrUOJFWYaJOOZhUleBaSmg8AW9rsZuLl98pexghCwEb9hh1mfkSUWpvRJFyVC7xblQa
JvLu5tc1TJLKtYP5uUrRmDEufA==
```
You can use `openssl ocsp -respin file -resp_text` to verify the format, which will give you something like this :
```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: C17DC2EDAF9ABBD01FF2DC7FB5C7C2C4593047AF
    Produced At: Dec 29 13:19:09 2022 GMT
    Responses:
    Certificate ID:
      Hash Algorithm: sha1
      Issuer Name Hash: 467F6C7AF3946017DA85E1ACE9BA717A2CCEF939
      Issuer Key Hash: C17DC2EDAF9ABBD01FF2DC7FB5C7C2C4593047AF
      Serial Number: 094E315FA6ADB9BC3EA20564A7B22EE6EBAA55E0
    Cert Status: good
    This Update: Dec 29 13:19:09 2022 GMT
    Next Update: Dec 30 13:19:08 2022 GMT

    Signature Algorithm: sha256WithRSAEncryption
         90:88:35:8d:fd:58:e6:09:b6:14:1d:1e:01:d8:1f:3f:9f:e1:
         d0:27:5d:24:16:32:0f:4a:7c:4a:fc:17:75:34:d4:f9:47:9e:
         fb:bc:d4:85:3c:0d:ce:ad:e8:9a:8b:12:2c:c8:09:db:21:23:
         12:ff:ef:6a:2e:17:82:f0:9e:27:eb:8b:be:13:19:00:3c:e0:
         9a:27:cd:c3:fe:7c:a3:de:05:ed:16:d8:f6:df:57:a0:a8:62:
         a1:2f:6d:37:44:13:ff:2e:c6:cf:2c:f5:ea:f0:fe:bd:86:2a:
         91:6f:0f:bd:be:ae:79:12:f9:03:74:14:01:15:33:79:46:68:
         53:6e:28:9a:4b:31:17:7b:26:55:b0:b3:33:c7:33:04:0a:de:
         e7:27:5e:8c:a0:d2:e8:68:e7:31:c4:d9:aa:0f:86:82:05:58:
         24:c4:bb:66:87:07:55:bc:15:46:fe:f9:c4:5a:3e:33:fe:cf:
         72:0e:fc:4c:d2:7e:2a:da:d4:38:91:56:61:a2:4e:39:98:54:
         95:e0:5a:4a:68:3c:01:6f:6b:b1:9b:8b:97:df:29:7b:18:21:
         0b:01:1b:f6:18:75:99:f9:12:51:6a:6f:44:91:72:54:2e:f1:
         6e:54:1a:26:f2:ee:e6:d7:35:4c:92:ca:b5:83:f9:b9:4a:d1:
         98:31:2e:7c
```
### Licence
* AGPL 3.0
