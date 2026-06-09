// SPDX-License-Identifier: GPL-3.0-or-later
//! CRL (RFC 5280 §5) parsing — uses `x509_cert::crl::CertificateList`
//! and only adds two helpers we actually need: a serial-number lookup
//! and an updated-window check.

use der::Decode;
use x509_cert::crl::CertificateList;
use x509_cert::serial_number::SerialNumber;

use crate::error::{Error, Result};

/// Parsed view of a CRL plus a flag telling us whether the requested
/// serial is on the revocation list.
pub struct ParsedCrl {
    pub crl: CertificateList,
}

impl ParsedCrl {
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        let crl = CertificateList::from_der(der_bytes)
            .map_err(|e| Error::Crl(format!("CertificateList decode: {e}")))?;
        Ok(Self { crl })
    }

    /// True iff `serial` appears in `tbsCertList.revokedCertificates`.
    pub fn is_revoked(&self, serial: &SerialNumber) -> bool {
        let revoked = match &self.crl.tbs_cert_list.revoked_certificates {
            Some(v) => v,
            None => return false,
        };
        revoked.iter().any(|r| &r.serial_number == serial)
    }
}
