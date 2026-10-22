//! Strict, offline license verification. Only a public key is needed by the client.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const PRODUCT: &str = "card-demo";
pub const VERSION: u8 = 1;
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 2048;
pub const SIGNING_DOMAIN: &[u8] = b"card-demo/license/v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct License {
    pub version: u8,
    pub product: String,
    pub license_id: String,
    pub subject: String,
    pub device_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidToken,
    InvalidSignature,
    WrongProduct,
    WrongDevice,
    NotYetValid,
    Expired,
    KeyError,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::InvalidSignature => "invalid_signature",
            Self::WrongProduct => "wrong_product",
            Self::WrongDevice => "wrong_device",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::KeyError => "key_error",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidToken => "卡密格式无效或字段超出允许范围",
            Self::InvalidSignature => "卡密签名无效，内容可能被修改",
            Self::WrongProduct => "卡密不适用于此产品或版本",
            Self::WrongDevice => "卡密与当前设备不匹配",
            Self::NotYetValid => "卡密尚未生效，请检查系统时间",
            Self::Expired => "卡密已过期",
            Self::KeyError => "内置验证公钥无效，请重新初始化并构建客户端",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

pub fn is_device_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_fields(license: &License) -> Result<(), Error> {
    if license.version != VERSION || license.product != PRODUCT {
        return Err(Error::WrongProduct);
    }
    if license.license_id.is_empty()
        || license.license_id.len() > 64
        || !license
            .license_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || license.subject.trim().is_empty()
        || license.subject.len() > 120
        || license.subject.chars().any(char::is_control)
        || !is_device_id(&license.device_id)
        || license.issued_at == 0
        || license.expires_at <= license.issued_at
        || license.expires_at - license.issued_at > 366 * 24 * 60 * 60
    {
        return Err(Error::InvalidToken);
    }
    Ok(())
}

pub fn parse_public_key(value: &str) -> Result<VerifyingKey, Error> {
    let value = value.trim();
    if value.len() != 64 {
        return Err(Error::KeyError);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(Error::KeyError),
        };
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Error::KeyError)?;
    if key.is_weak() {
        return Err(Error::KeyError);
    }
    Ok(key)
}

pub fn signing_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + payload.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(payload);
    message
}

/// Verify the exact signed bytes before interpreting their strict JSON representation.
/// `now` and `device_id` are supplied by the trusted client boundary, never by its JSON request.
pub fn verify(
    token: &str,
    key: &VerifyingKey,
    device_id: &str,
    now: u64,
) -> Result<License, Error> {
    if token.len() > MAX_TOKEN_BYTES || !token.is_ascii() || !is_device_id(device_id) {
        return Err(Error::InvalidToken);
    }
    let mut parts = token.split('.');
    let (Some("L1"), Some(payload_text), Some(signature_text), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidToken);
    };
    if payload_text.is_empty()
        || payload_text.len() > MAX_PAYLOAD_BYTES.div_ceil(3) * 4
        || signature_text.len() != 86
    {
        return Err(Error::InvalidToken);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_text)
        .map_err(|_| Error::InvalidToken)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::InvalidToken);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_text)
        .map_err(|_| Error::InvalidToken)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::InvalidToken)?;
    key.verify_strict(&signing_message(&payload), &signature)
        .map_err(|_| Error::InvalidSignature)?;
    let license: License = serde_json::from_slice(&payload).map_err(|_| Error::InvalidToken)?;
    validate_fields(&license)?;
    if license.device_id != device_id {
        return Err(Error::WrongDevice);
    }
    if now < license.issued_at {
        return Err(Error::NotYetValid);
    }
    if now >= license.expires_at {
        return Err(Error::Expired);
    }
    Ok(license)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture() -> (SigningKey, License) {
        // Only a deterministic UNIT TEST key; production has no fallback key.
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let license = License {
            version: VERSION,
            product: PRODUCT.into(),
            license_id: "TEST-001".into(),
            subject: "演示用户".into(),
            device_id: "a".repeat(64),
            issued_at: 1000,
            expires_at: 2000,
        };
        (key, license)
    }

    fn sign_raw(key: &SigningKey, payload: &[u8]) -> String {
        let signature = key.sign(&signing_message(payload));
        format!(
            "L1.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn sign(key: &SigningKey, license: &License) -> String {
        sign_raw(key, &serde_json::to_vec(license).unwrap())
    }

    #[test]
    fn valid_and_time_boundaries() {
        let (key, license) = fixture();
        let token = sign(&key, &license);
        for now in [1000, 1500, 1999] {
            assert_eq!(
                verify(&token, &key.verifying_key(), &license.device_id, now),
                Ok(license.clone())
            );
        }
        assert_eq!(
            verify(&token, &key.verifying_key(), &license.device_id, 999),
            Err(Error::NotYetValid)
        );
        assert_eq!(
            verify(&token, &key.verifying_key(), &license.device_id, 2000),
            Err(Error::Expired)
        );
    }

    #[test]
    fn tampered_payload_signature_and_wrong_key_rejected() {
        let (key, mut license) = fixture();
        let token = sign(&key, &license);
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        license.subject = "篡改用户".into();
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&license).unwrap());
        assert_eq!(
            verify(
                &parts.join("."),
                &key.verifying_key(),
                &license.device_id,
                1500
            ),
            Err(Error::InvalidSignature)
        );
        let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        signature[0] ^= 1;
        parts[1] = token.split('.').nth(1).unwrap().into();
        parts[2] = URL_SAFE_NO_PAD.encode(signature);
        assert_eq!(
            verify(
                &parts.join("."),
                &key.verifying_key(),
                &license.device_id,
                1500
            ),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify(
                &token,
                &SigningKey::from_bytes(&[0x43; 32]).verifying_key(),
                &license.device_id,
                1500
            ),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn wrong_device_product_version_and_lifetime_rejected() {
        let (key, mut license) = fixture();
        assert_eq!(
            verify(
                &sign(&key, &license),
                &key.verifying_key(),
                &"b".repeat(64),
                1500
            ),
            Err(Error::WrongDevice)
        );
        license.product = "other-product".into();
        assert_eq!(validate_fields(&license), Err(Error::WrongProduct));
        license.product = PRODUCT.into();
        license.version = 2;
        assert_eq!(validate_fields(&license), Err(Error::WrongProduct));
        license.version = VERSION;
        license.expires_at = license.issued_at;
        assert_eq!(validate_fields(&license), Err(Error::InvalidToken));
        license.expires_at = u64::MAX;
        assert_eq!(validate_fields(&license), Err(Error::InvalidToken));
    }

    #[test]
    fn strict_json_types_unknown_and_duplicate_fields() {
        let (key, license) = fixture();
        let base = serde_json::to_string(&license).unwrap();
        for payload in [
            base.replace("\"version\":1", "\"version\":\"1\""),
            base.replace("\"issued_at\":1000", "\"issued_at\":-1"),
            base.replace("\"issued_at\":1000", "\"issued_at\":1000.0"),
            base.replace("\"issued_at\":1000", "\"issued_at\":18446744073709551616"),
            base.replace("\"version\":1", "\"version\":1,\"admin\":true"),
            base.replace("\"version\":1", "\"version\":1,\"version\":1"),
        ] {
            assert_eq!(
                verify(
                    &sign_raw(&key, payload.as_bytes()),
                    &key.verifying_key(),
                    &license.device_id,
                    1500
                ),
                Err(Error::InvalidToken)
            );
        }
    }

    #[test]
    fn malformed_and_oversized_input_rejected() {
        let (key, license) = fixture();
        for token in [
            "".into(),
            "L1.a.b".into(),
            "x".repeat(MAX_TOKEN_BYTES + 1),
            format!("{}.", sign(&key, &license)),
        ] {
            assert_eq!(
                verify(&token, &key.verifying_key(), &license.device_id, 1500),
                Err(Error::InvalidToken)
            );
        }
    }

    #[test]
    fn weak_or_malformed_public_keys_rejected() {
        assert!(parse_public_key(&"00".repeat(32)).is_err());
        assert!(parse_public_key("not-a-key").is_err());
    }

    #[test]
    fn signatures_from_another_protocol_are_rejected() {
        let (key, license) = fixture();
        let payload = serde_json::to_vec(&license).unwrap();
        let signature_without_domain = key.sign(&payload);
        let token = format!(
            "L1.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature_without_domain.to_bytes())
        );
        assert_eq!(
            verify(&token, &key.verifying_key(), &license.device_id, 1500),
            Err(Error::InvalidSignature)
        );
    }
}
