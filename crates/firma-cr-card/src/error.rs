// SPDX-License-Identifier: GPL-3.0-or-later
//! Error type for the card-access layer. Deliberately small — only the
//! failure modes the PKCS#11 client surfaces. The signer libraries wrap
//! these into their own crate-wide error via `From`.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("token has no readable certificate (CKA_VALUE missing or empty)")]
    NoCertificate,

    #[error("token has no signing private key (CKA_SIGN-capable RSA private key not found)")]
    NoSigningKey,
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        Error::Pkcs11(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
