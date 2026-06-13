// SPDX-License-Identifier: GPL-3.0-or-later
//! Signature verification — inverse of the signer chain.
//!
//! Three families, each parses the signed envelope, recomputes the
//! covered digests, RSA-verifies the signature against the signer
//! cert's public key, and walks the cert chain against the supplied
//! trust anchor.
//!
//! Public entry points:
//!
//!   * `cms::verify_detached(p7s, content, trust_root)`
//!   * `pades::verify_pdf(pdf, trust_root)`
//!   * `xades::verify_xml(xml, trust_root)`
//!
//! All return `Result<VerifyReport, Error>`. `VerifyReport` carries
//! a yes/no `ok` flag and a list of warnings (chain-build details,
//! revocation-data presence, etc.) so the CLI can surface what
//! contributed to the verdict.

pub mod chain;
pub mod cms;
pub mod pades;
pub mod revocation;
pub mod tsa;
pub mod xades;

/// One signer's verdict. A CMS SignedData can carry multiple
/// SignerInfo entries (counter-signers) and each one is validated
/// independently against the same content; this struct holds the
/// per-signer result. For XAdES (one `<ds:Signature>` per file)
/// and PAdES (one CAdES inside `/Type /Sig` per signature dict)
/// the verifier produces exactly one entry — the same shape, just
/// trivially length-1.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignerVerdict {
    pub ok: bool,
    pub signer_subject: Option<String>,
    pub signing_time: Option<String>,
    pub has_timestamp: bool,
    pub timestamp: Option<tsa::TimestampVerdict>,
    pub revocation: Option<revocation::RevocationVerdict>,
    pub archive_timestamp: Option<tsa::TimestampVerdict>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    /// First signer's subject DN (for back-compat with pre-12b
    /// single-signer reports). For multi-signer CMS use `signers`
    /// instead.
    pub signer_subject: Option<String>,
    pub signing_time: Option<String>,
    pub has_timestamp: bool,
    /// Result of verifying any embedded RFC 3161 TimeStampToken. `None`
    /// means no timestamp was present; `Some(verdict)` carries the
    /// per-token outcome — note `verdict.ok` is independent of the
    /// top-level `ok` only when `cert_internal` was requested.
    pub timestamp: Option<tsa::TimestampVerdict>,
    /// Result of validating any embedded -LT revocation values
    /// (`id-aa-ets-revocationValues` for CAdES/PAdES,
    /// `<xades:RevocationValues>` for XAdES).
    pub revocation: Option<revocation::RevocationVerdict>,
    /// Result of validating any embedded archive timestamp
    /// (id-aa-ets-archiveTimestamp / PAdES /DocTimeStamp). `None`
    /// when no archive timestamp is present.
    pub archive_timestamp: Option<tsa::TimestampVerdict>,
    pub warnings: Vec<String>,
    /// One entry per SignerInfo (CMS) or per ds:Signature element
    /// (XAdES) the verifier saw. The top-level `ok` is the AND of
    /// every `signers[i].ok`. For single-signer artifacts this is
    /// length 1 and mirrors the legacy top-level fields.
    pub signers: Vec<SignerVerdict>,
}

impl VerifyReport {
    pub fn pretty(&self) -> String {
        let head = if self.ok { "OK" } else { "FAILED" };
        let mut out = format!("verdict: {head}\n");
        if self.signers.len() > 1 {
            // Multi-signer CMS — render one block per signer with
            // an explicit index, no flat top-level fields.
            for (i, s) in self.signers.iter().enumerate() {
                append_signer_block(&mut out, Some(i), s);
            }
        } else if let Some(s) = self.signers.first() {
            // Single signer — render in-line at the top level.
            append_signer_block(&mut out, None, s);
        } else {
            // No signers at all (parse error before SignerInfo loop).
            // Fall back to legacy top-level fields.
            if let Some(s) = &self.signer_subject {
                out.push_str(&format!("  signer:        {s}\n"));
            }
        }
        for w in &self.warnings {
            out.push_str(&format!("  warning:       {w}\n"));
        }
        out
    }
}

fn append_signer_block(out: &mut String, index: Option<usize>, s: &SignerVerdict) {
    let prefix = match index {
        Some(i) => {
            let head = if s.ok { "OK" } else { "FAILED" };
            out.push_str(&format!("  signer #{}:     {head}\n", i + 1));
            "  "
        }
        None => "",
    };
    if let Some(sub) = &s.signer_subject {
        out.push_str(&format!("  {prefix}signer:        {sub}\n"));
    }
    if let Some(t) = &s.signing_time {
        out.push_str(&format!("  {prefix}signing time:  {t}\n"));
    }
    out.push_str(&format!("  {prefix}has timestamp: {}\n", s.has_timestamp));
    if let Some(ts) = &s.timestamp {
        let ts_head = if ts.ok { "OK" } else { "FAILED" };
        out.push_str(&format!("  {prefix}timestamp:     {ts_head}\n"));
        if let Some(t) = &ts.tsa_subject {
            out.push_str(&format!("    {prefix}TSA cert:    {t}\n"));
        }
        if let Some(t) = &ts.gen_time {
            out.push_str(&format!("    {prefix}gen time:    {t}\n"));
        }
        for w in &ts.warnings {
            out.push_str(&format!("    {prefix}warning:     {w}\n"));
        }
    }
    if let Some(rv) = &s.revocation {
        let rv_head = if rv.ok { "OK" } else { "FAILED" };
        out.push_str(&format!("  {prefix}revocation:    {rv_head}\n"));
        if let Some(st) = &rv.ocsp_status {
            out.push_str(&format!("    {prefix}OCSP status: {st}\n"));
        }
        for w in &rv.warnings {
            out.push_str(&format!("    {prefix}warning:     {w}\n"));
        }
    }
    if let Some(at) = &s.archive_timestamp {
        let at_head = if at.ok { "OK" } else { "FAILED" };
        out.push_str(&format!("  {prefix}archive ts:    {at_head}\n"));
        if let Some(t) = &at.tsa_subject {
            out.push_str(&format!("    {prefix}TSA cert:    {t}\n"));
        }
        if let Some(t) = &at.gen_time {
            out.push_str(&format!("    {prefix}gen time:    {t}\n"));
        }
        for w in &at.warnings {
            out.push_str(&format!("    {prefix}warning:     {w}\n"));
        }
    }
    for w in &s.warnings {
        out.push_str(&format!("  {prefix}warning:       {w}\n"));
    }
}

/// Options controlling verification strictness.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOptions {
    /// If true, accept any TimeStampToken whose own signer chain is
    /// internally consistent, even if it doesn't anchor to the same
    /// trust root as the document signer. Failure to anchor becomes
    /// a warning instead of a hard verification failure.
    pub cert_internal: bool,
    /// If `Some(t)`, all time-relative checks (cert validity
    /// window today; OCSP `nextUpdate` and embedded timestamp
    /// `genTime` are planned follow-ups) are evaluated as if "now"
    /// were `t`. Use this when verifying a signature that was made
    /// long ago — the signer cert is expired *now* but was valid
    /// at the embedded `signingTime`. Default `None` =
    /// `SystemTime::now()`.
    pub validation_time: Option<std::time::SystemTime>,
    /// Revocation policy. When `true`, a signature that carries **no** embedded
    /// revocation data (OCSP/CRL) is a hard failure rather than a pass — set this
    /// when verifying long-term `-LT`/`-LTA` signatures, where revocation
    /// evidence is mandatory. Default `false` keeps `-B-B`/`-T` signatures (which
    /// legitimately carry no revocation data) passing, and a *present-but-failing*
    /// revocation check is always a hard failure regardless of this flag.
    pub require_revocation: bool,
}
