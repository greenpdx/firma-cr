//! Typed request/response contracts for the `/dyn` endpoints (DESIGN.md,
//! reports/29). Requests are parsed from the query params ([`DynRequest`]);
//! responses serialize to JSON.
//!
//! The **request** shapes are grounded in the observed query params. The
//! **response** field names are the best-known from the client JS; the ones not
//! yet confirmed against live traffic are flagged `[unconfirmed]` — a `tcpdump`
//! of a real flow (needs a card) will finalize them.

use serde::{Deserialize, Serialize};

use crate::agent::dyn_request::DynRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    MissingParam(&'static str),
    BadParam(&'static str),
    UnknownOperation,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::MissingParam(p) => write!(f, "missing parameter '{p}'"),
            ApiError::BadParam(p) => write!(f, "bad parameter '{p}'"),
            ApiError::UnknownOperation => write!(f, "unknown operation type"),
        }
    }
}
impl std::error::Error for ApiError {}

/// Cryptoshell operation type — `&type=SIGN|ENCRYPT|SIGNENCRYPT|OPEN`
/// (cryptoshellapp-common.js: SIGN=0, ENCRYPT=1, SIGNENCRYPT=2, OPEN=3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Sign,
    Encrypt,
    SignEncrypt,
    Open,
}
impl OperationType {
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "SIGN" => Self::Sign,
            "ENCRYPT" => Self::Encrypt,
            "SIGNENCRYPT" => Self::SignEncrypt,
            "OPEN" => Self::Open,
            _ => return None,
        })
    }
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Sign => "SIGN",
            Self::Encrypt => "ENCRYPT",
            Self::SignEncrypt => "SIGNENCRYPT",
            Self::Open => "OPEN",
        }
    }
}

// ---------------------------------------------------------------------------
// Requests (parsed from the /dyn query params)
// ---------------------------------------------------------------------------

/// `/dyn/login?env=&token=<handle>&pin=<index>&e=<b64 RSA-encrypted PIN>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub token: String,
    pub pin_index: u32,
    pub encrypted_pin_b64: String,
}
impl LoginRequest {
    pub fn from_dyn(r: &DynRequest) -> Result<Self, ApiError> {
        Ok(Self {
            token: r.param("token").ok_or(ApiError::MissingParam("token"))?.to_string(),
            pin_index: r
                .param("pin")
                .ok_or(ApiError::MissingParam("pin"))?
                .parse()
                .map_err(|_| ApiError::BadParam("pin"))?,
            encrypted_pin_b64: r.param("e").ok_or(ApiError::MissingParam("e"))?.to_string(),
        })
    }
}

/// `/dyn/cryptoshell_build?env=&type=SIGN&sign_cert=<handle>&sign_key=<handle>&files=<json array>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoshellBuildRequest {
    pub op_type: OperationType,
    pub sign_cert: String,
    pub sign_key: String,
    pub files: Vec<String>,
}
impl CryptoshellBuildRequest {
    pub fn from_dyn(r: &DynRequest) -> Result<Self, ApiError> {
        let op_type =
            OperationType::from_wire(r.param("type").ok_or(ApiError::MissingParam("type"))?)
                .ok_or(ApiError::UnknownOperation)?;
        let files: Vec<String> =
            serde_json::from_str(r.param("files").ok_or(ApiError::MissingParam("files"))?)
                .map_err(|_| ApiError::BadParam("files"))?;
        Ok(Self {
            op_type,
            sign_cert: r.param("sign_cert").ok_or(ApiError::MissingParam("sign_cert"))?.to_string(),
            sign_key: r.param("sign_key").ok_or(ApiError::MissingParam("sign_key"))?.to_string(),
            files,
        })
    }
}

// ---------------------------------------------------------------------------
// Responses (serialized to JSON)
// ---------------------------------------------------------------------------

/// `create_env` response — the env id and the public key the client encrypts
/// the PIN with. [confirmed: the handshake delivers `env` + `pubKeyPem`]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateEnvResponse {
    #[serde(rename = "envId")]
    pub env_id: String,
    #[serde(rename = "pubKeyPem")]
    pub pub_key_pem: String,
}

/// One entry from `get_certstore_certificates`. `handle` feeds
/// `sign_cert`/`sign_key`. [field names best-known from the client; unconfirmed]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificate {
    pub handle: String,
    pub label: String,
    #[serde(rename = "subjectDN")]
    pub subject_dn: String,
    #[serde(rename = "issuerDN")]
    pub issuer_dn: String,
    pub serial: String,
    /// DER certificate, base64.
    #[serde(rename = "certB64")]
    pub cert_b64: String,
}

/// `login` result. [unconfirmed shape]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginResponse {
    pub success: bool,
    #[serde(rename = "triesLeft", skip_serializing_if = "Option::is_none")]
    pub tries_left: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_type_round_trips() {
        for s in ["SIGN", "ENCRYPT", "SIGNENCRYPT", "OPEN"] {
            assert_eq!(OperationType::from_wire(s).unwrap().as_wire(), s);
        }
        assert!(OperationType::from_wire("BOGUS").is_none());
    }

    #[test]
    fn login_request_parses() {
        let r = DynRequest::parse("/dyn/login?env=E&token=5&pin=0&e=QUJD").unwrap();
        let lr = LoginRequest::from_dyn(&r).unwrap();
        assert_eq!(lr.token, "5");
        assert_eq!(lr.pin_index, 0);
        assert_eq!(lr.encrypted_pin_b64, "QUJD");
    }

    #[test]
    fn login_request_missing_and_bad_params() {
        let r = DynRequest::parse("/dyn/login?env=E&token=5&e=QUJD").unwrap();
        assert_eq!(LoginRequest::from_dyn(&r), Err(ApiError::MissingParam("pin")));
        let r = DynRequest::parse("/dyn/login?env=E&token=5&pin=xx&e=QUJD").unwrap();
        assert_eq!(LoginRequest::from_dyn(&r), Err(ApiError::BadParam("pin")));
    }

    #[test]
    fn cryptoshell_build_parses_sign() {
        // files = encodeURIComponent('["a.pdf","b.pdf"]')
        let r = DynRequest::parse(
            "/dyn/cryptoshell_build?env=E&type=SIGN&sign_cert=10&sign_key=11&files=%5B%22a.pdf%22%2C%22b.pdf%22%5D",
        )
        .unwrap();
        let b = CryptoshellBuildRequest::from_dyn(&r).unwrap();
        assert_eq!(b.op_type, OperationType::Sign);
        assert_eq!(b.sign_cert, "10");
        assert_eq!(b.sign_key, "11");
        assert_eq!(b.files, vec!["a.pdf".to_string(), "b.pdf".to_string()]);
    }

    #[test]
    fn cryptoshell_build_rejects_unknown_type_and_bad_files() {
        let r = DynRequest::parse("/dyn/cryptoshell_build?env=E&type=NOPE&sign_cert=1&sign_key=2&files=%5B%5D").unwrap();
        assert_eq!(CryptoshellBuildRequest::from_dyn(&r), Err(ApiError::UnknownOperation));
        let r = DynRequest::parse("/dyn/cryptoshell_build?env=E&type=SIGN&sign_cert=1&sign_key=2&files=not-json").unwrap();
        assert_eq!(CryptoshellBuildRequest::from_dyn(&r), Err(ApiError::BadParam("files")));
    }

    #[test]
    fn create_env_response_serializes_to_protocol_keys() {
        let resp = CreateEnvResponse { env_id: "abc".into(), pub_key_pem: "PEM".into() };
        assert_eq!(serde_json::to_string(&resp).unwrap(), r#"{"envId":"abc","pubKeyPem":"PEM"}"#);
    }

    #[test]
    fn certificate_serializes_with_renamed_fields() {
        let c = Certificate {
            handle: "7".into(),
            label: "Firma".into(),
            subject_dn: "CN=X".into(),
            issuer_dn: "CN=CA".into(),
            serial: "01".into(),
            cert_b64: "AAA".into(),
        };
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["handle"], "7");
        assert_eq!(j["subjectDN"], "CN=X");
        assert_eq!(j["issuerDN"], "CN=CA");
        assert_eq!(j["certB64"], "AAA");
    }

    #[test]
    fn login_response_omits_tries_when_success() {
        let ok = LoginResponse { success: true, tries_left: None };
        assert_eq!(serde_json::to_string(&ok).unwrap(), r#"{"success":true}"#);
        let bad = LoginResponse { success: false, tries_left: Some(2) };
        assert_eq!(serde_json::to_string(&bad).unwrap(), r#"{"success":false,"triesLeft":2}"#);
    }
}
