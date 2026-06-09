// SPDX-License-Identifier: GPL-3.0-or-later
//! Crate-level error type. Wraps every failure mode (PKCS#11, CMS
//! construction, PDF parsing, XML signing, network) into one enum so
//! `Result<T, Error>` propagates cleanly. Where the upstream crate
//! exposes a stable `From` we use it; otherwise we convert via
//! `to_string()` to stay independent of upstream API churn.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("token has no readable certificate (CKA_VALUE missing or empty)")]
    NoCertificate,

    #[error("token has no signing private key (CKA_SIGN-capable RSA private key not found)")]
    NoSigningKey,

    #[error("certificate parse failed: {0}")]
    CertParse(String),

    #[error("CMS construction failed: {0}")]
    Cms(String),

    #[error("PDF error: {0}")]
    Pdf(String),

    #[error("PDF already contains a signature; pass --allow-resign to add another")]
    PdfAlreadySigned,

    #[error("XML error: {0}")]
    Xml(String),

    #[error("XAdES error: {0}")]
    Xades(String),

    #[error("TSA request failed: {0}")]
    Tsa(String),

    #[error("OCSP request failed: {0}")]
    Ocsp(String),

    #[error("CRL fetch failed: {0}")]
    Crl(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DER encoding error: {0}")]
    Der(String),

    #[error("invalid argument: {0}")]
    InvalidArg(String),
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        Error::Pkcs11(e.to_string())
    }
}

impl From<firma_cr_card::CardError> for Error {
    fn from(e: firma_cr_card::CardError) -> Self {
        use firma_cr_card::CardError as C;
        match e {
            C::Pkcs11(s) => Error::Pkcs11(s),
            C::NoCertificate => Error::NoCertificate,
            C::NoSigningKey => Error::NoSigningKey,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
