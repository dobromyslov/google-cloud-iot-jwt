use core::result::Result;
use p256::{
    SecretKey,
    ecdsa::{SigningKey, Signature, signature::Signer},
};
use pem_rfc7468::decode;
use base64ct::{ Base64Unpadded, Encoding };
use ufmt::uwrite;
use heapless::String;

/// Calculates length of a base64 encoded without padding string
/// created from a plain source with the specified length.
/// This is a const function evaluated once only during compilation.
const fn base64_encoded_length(source_length: usize) -> usize {
    // return f64::ceil(source_length / 3 * 4)
    // Can't use floating points and f64::ceil() in constant functions
    // due to https://github.com/rust-lang/rust/issues/57241
    // Workaround:
    let v = source_length * 4;
    if v % 3 > 0 {
        v / 3 + 1
    } else {
        v / 3
    }
}

/// Calculates length of a base64 decoded bytes slice
/// created from a source with the specified length.
/// This is a const function evaluated once only during compilation.
const fn base64_decoded_length(source_length: usize) -> usize {
    // return f64::ceil(source_length / 4 * 3)
    // Can't use floating points and f64::ceil() in constant functions
    // due to https://github.com/rust-lang/rust/issues/57241
    // Workaround:
    let v = source_length * 3;
    if v % 4 > 0 {
        v / 4 + 1
    } else {
        v / 4
    }
}

/// ES256 JWT header JSON string = {"alg":"ES256","typ":"JWT"}.
const JWT_HEADER_MAX_LENGTH: usize = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}".len();

/// Length of the JWT header encoded in Base64 without padding.
const JWT_HEADER_BASE64_MAX_LENGTH: usize = base64_encoded_length(JWT_HEADER_MAX_LENGTH);

/// See https://cloud.google.com/resource-manager/docs/creating-managing-projects#:~:text=Project%20ID%20requirements%3A,letters%2C%20numbers%2C%20and%20hyphens
const GOOGLE_PROJECT_NAME_MAX_LENGTH: usize = 30;

/// Lenght of the JSON envelope for Google JWT claims.
/// {"aud":"","iat":,"exp":}
const JWT_CLAIMS_ENVELOPE_MAX_LENGTH: usize = "{\"aud\":\"\",\"iat\":,\"exp\":}".len();

/// 64-bits usize max is 18446744073709551615
const TIMESTAMP_MAX_LENGTH: usize = "18446744073709551615".len();

/// JWT Claims JSON string consist of:
/// * JWT claims envelope {"aud":"","iat":,"exp":};
/// * Google project name;
/// * Timestamp issued at;
/// * Timestamp expires at.
///
/// Example:
/// {"aud":"your_google_cloud_project_name","iat":18446744073709465215,"exp":18446744073709551615}
const JWT_CLAIMS_MAX_LENGTH: usize = JWT_CLAIMS_ENVELOPE_MAX_LENGTH + GOOGLE_PROJECT_NAME_MAX_LENGTH
    + TIMESTAMP_MAX_LENGTH * 2;

/// Length of the JWT claims encoded in Base64 without padding.
const JWT_CLAIMS_BASE64_MAX_LENGTH: usize = base64_encoded_length(JWT_CLAIMS_MAX_LENGTH);

/// Length of an Elliptic Curves Signature ES256 signature in binary format.
const ES256_SIGNATURE_MAX_LENGTH: usize = 64;

/// Length of an Elliptica Curves ES256 signature in Base64 format without padding.
const ES256_SIGNATURE_BASE64_MAX_LENGTH: usize = base64_encoded_length(ES256_SIGNATURE_MAX_LENGTH);

/// JWT ES256 = "base64_unpadded(headers).base64_unpadded(claims).base64_unpadded(signature)":
/// * Header characters base64 encoded without padding;
/// * Dot delimiter;
/// * Claims base64 encoded without padding;
/// * Dot delimiter;
/// * ES256 signature Base64 encoded without padding.
///
/// Example:
/// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2dvb2dsZV9jbG91ZF9wcm9qZWN0X25hbWUiLCJpYXQiOjE4NDQ2NzQ0MDczNzA5NDY1MjE1LCJleHAiOjE4NDQ2NzQ0MDczNzA5NTUxNjE1fQ.pDUQITCkCPZVuieg8K44jSz7cvY967pG+bqMDpevZmTBnrTxzV8vcStmtfo8excLAONUep821sxclJbLBdWFrA
pub const JWT_ES256_MAX_LENGTH: usize = JWT_HEADER_BASE64_MAX_LENGTH + 1
    + JWT_CLAIMS_BASE64_MAX_LENGTH + 1
    + ES256_SIGNATURE_BASE64_MAX_LENGTH;

/// JWT default lifetime is 24 hours.
const JWT_LIFETIME: usize = 24 * 60 * 60;

/// Length of an Elliptic Curves private key stored in base64 with padding sec1 PEM format is 164
/// characters.
const EC_PRIVATE_KEY_SEC1_BASE64_MAX_SIZE: usize = 164;

/// Length of an Elliptic Curves private key stored in binary sec1 DER format.
const EC_PRIVATE_KEY_BINARY_MAX_SIZE: usize = base64_decoded_length(EC_PRIVATE_KEY_SEC1_BASE64_MAX_SIZE);

/// Decodes Elliptic Curves private key from PEM.
/// PEM should be in Elliptic Curves sec1 PEM format with correct label "EC PRIVATE KEY".
/// Example:
/// -----BEGIN EC PRIVATE KEY-----
// MHcCAQEEIDMvJjBfq3YVCHHeJj8pbsGITyhoHjkwg9o+3pLZkAAWoAoGCCqGSM49
// AwEHoUQDQgAE5JHMOhIYK0AwPmvWXpRz2tU4OaC9A2+j8wTPDYmDLT1C3hV5ZeWr
// iuPXSxsC6gVceKszCX/sJkcgQVXVkE3nOg==
// -----END EC PRIVATE KEY-----
fn get_ec_private_key_from_pem<'a>(ec_private_pem: &'a str) -> Result<SecretKey, &'static str> {
    let mut buffer = [0_u8; EC_PRIVATE_KEY_BINARY_MAX_SIZE];
    let (label, buffer) = decode(ec_private_pem.as_bytes(), &mut buffer)
        .map_err(|_| "Can't decode PEM string")?;

    if label != "EC PRIVATE KEY" {
        return Err("Unsupported secret key. The key label must be 'EC PRIVATE KEY'");
    }

    Ok(SecretKey::from_sec1_der(&buffer)
        .map_err(|_| "Can't decode secret key")?
    )
}

/// Signs a message with ES256 signature using Elliptic Curves secret key in PEM format.
fn sign_es256(message: &str, ec_private_pem: &str) -> Result<Signature, &'static str> {
    Ok(
        SigningKey::from(
            get_ec_private_key_from_pem(ec_private_pem)?
        ).sign(message.as_bytes())
    )
}

/// Creates Google IOT JWT using ES256 signature.
/// Returns heapless string no longer than JWT_ES256_MAX_LENGTH characters.
pub fn create_google_jwt_es256(
    project_name: &str,
    private_key_pem: &str,
    timestamp: usize,
) -> Result<String<JWT_ES256_MAX_LENGTH>, &'static str> {
    if project_name.len() < 6 || project_name.len() > 30 {
        return Err("Project name should be 6-30 characters in length");
    }

    let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
    let mut claims: String<JWT_CLAIMS_MAX_LENGTH> = String::new();
    uwrite!(
        claims,
        "{{\"aud\":\"{}\",\"iat\":{},\"exp\":{}}}",
        project_name, timestamp, timestamp + JWT_LIFETIME
    ).map_err(|_| "Can not create JSON string for claims")?;

    let mut result: String<JWT_ES256_MAX_LENGTH> = String::new();

    // Encode header
    result.push_str(
        Base64Unpadded::encode(
            header.as_bytes(),
            &mut [0_u8; JWT_HEADER_BASE64_MAX_LENGTH]
        ).map_err(|_| "Can not encode JWT header to base64")?
    ).map_err(|_| "Can not push to the JWT string")?;

    result.push('.').map_err(|_|"Can not push to the JWT string")?;

    // Encode claims
    result.push_str(
        Base64Unpadded::encode(
            claims.as_bytes(),
            &mut [0_u8; JWT_CLAIMS_BASE64_MAX_LENGTH]
        ).map_err(|_| "Can not encode JWT claims to base64")?
    ).map_err(|_| "Can not push to JWT string")?;

    // Sign concatenated "base64(header).base64(claims)" with ES256 signature
    let signature = sign_es256(result.as_str(), private_key_pem)
        .map_err(|_| "Can not sign JWT")?;

    // Encode signature to the base64 format and join it to the JWT result
    result.push('.').map_err(|_| "Can not push to JWT string")?;
    result.push_str(
        Base64Unpadded::encode(
            signature.as_ref(),
            &mut [0_u8; JWT_ES256_MAX_LENGTH]
        ).map_err(|_| "Can not encode JWT signature to base64")?
    ).map_err(|_| "Can not push to JWT string")?;

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    const EC_PRIVATE_KEY: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDMvJjBfq3YVCHHeJj8pbsGITyhoHjkwg9o+3pLZkAAWoAoGCCqGSM49
AwEHoUQDQgAE5JHMOhIYK0AwPmvWXpRz2tU4OaC9A2+j8wTPDYmDLT1C3hV5ZeWr
iuPXSxsC6gVceKszCX/sJkcgQVXVkE3nOg==
-----END EC PRIVATE KEY-----
";
    const MESSAGE: &str = "TEST MESSAGE";


    #[test]
    fn test_jwt_es256_max_length() {
        assert_eq!(JWT_ES256_MAX_LENGTH, 250);
    }

    #[test]
    fn test_base64_encoded_length() {

    }

    #[test]
    fn test_get_ec_private_key_from_pem() {
        let secret_key = get_ec_private_key_from_pem(EC_PRIVATE_KEY).unwrap();
        assert_eq!(
            &secret_key.to_be_bytes()[..],
            &hex!("332f26305fab76150871de263f296ec1884f28681e393083da3ede92d9900016")[..]
        );
    }

    #[test]
    fn test_sign_es256() {
        let signature = sign_es256(MESSAGE, EC_PRIVATE_KEY).unwrap();
        assert_eq!(
            signature.as_ref(),
            &hex!("2e9f9b3d58d23263f2275792982b5cb033ca95f529d28fb9e0b0702f169db60ac1cfaed71c8bd9f2af9d87adecf500ffebfee69e17ac65e24ab31066e2db4885")[..]
        );
    }

    #[test]
    fn test_verify_signature() {
        use p256::ecdsa::{VerifyingKey, signature::Verifier, signature::Signature as _};

        let verify_key = VerifyingKey::from(
            &SigningKey::from(get_ec_private_key_from_pem(EC_PRIVATE_KEY).unwrap())
        );
        assert!(verify_key.verify(
            MESSAGE.as_bytes(),
            &Signature::from_bytes(
                &hex!("2e9f9b3d58d23263f2275792982b5cb033ca95f529d28fb9e0b0702f169db60ac1cfaed71c8bd9f2af9d87adecf500ffebfee69e17ac65e24ab31066e2db4885")[..]
            ).unwrap()
        ).is_ok());
    }

    #[test]
    fn test_create_google_jwt_es256() {
        let jwt = create_google_jwt_es256(
            "your_google_cloud_project_name",
            EC_PRIVATE_KEY,
            18446744073709465215
        ).unwrap();

        assert_eq!(
            jwt,
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ5b3VyX2dvb2dsZV9jbG91ZF9wcm9qZWN0X25hbWUiLCJpYXQiOjE4NDQ2NzQ0MDczNzA5NDY1MjE1LCJleHAiOjE4NDQ2NzQ0MDczNzA5NTUxNjE1fQ.pDUQITCkCPZVuieg8K44jSz7cvY967pG+bqMDpevZmTBnrTxzV8vcStmtfo8excLAONUep821sxclJbLBdWFrA"
        );

        assert_eq!(jwt.len(), JWT_ES256_MAX_LENGTH);
    }
}
