//! firma-cr-core — CLI entry point.
//!
//! Three signing modes (cms / pdf / xml) plus a diagnostic `info`
//! mode that prints the loaded module's library + token info + the
//! parsed signing certificate. Each signing subcommand will be
//! filled in over Phase 2-4; Phase 1 lands only `info`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use firma_cr_core::cades::CadesBuilder;
use firma_cr_core::cert::SignerCert;
use firma_cr_core::digest::HashAlgo;
use firma_cr_core::pkcs11_client::CardClient;
use firma_cr_core::signer::CardSigner;

const DEFAULT_MODULE: &str = "/usr/lib/firma-cr/libfirma_cr_pkcs11.so";

#[derive(Parser, Debug)]
#[command(
    name = "firma-cr-core",
    version,
    about = "ETSI digital signature CLI (PAdES + CAdES + XAdES) for Costa Rica BCCR Firma Digital cards",
    long_about = None,
)]
struct Cli {
    /// PKCS#11 module .so to drive. Override only if your module
    /// isn't at /usr/lib/firma-cr/libfirma_cr_pkcs11.so.
    #[arg(long, env = "FIRMA_CR_MODULE", default_value = DEFAULT_MODULE, global = true)]
    module: PathBuf,

    /// Token slot index (default: first slot with a present token).
    #[arg(long, env = "FIRMA_CR_SLOT", global = true)]
    slot: Option<usize>,

    /// Override the on-card certificate with a file on disk (DER or
    /// PEM). Useful when the token holds only the leaf cert and you
    /// need to include the issuer chain in the signature.
    #[arg(long, global = true)]
    cert_file: Option<PathBuf>,

    /// Multi-cert PEM bundle (intermediates + optional root) to
    /// embed alongside the leaf cert in the signature. Verifiers
    /// that don't have BCCR's chain installed use these to build
    /// the trust path.
    #[arg(long, global = true)]
    include_chain: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print module/library/token/cert info. No PIN required.
    Info,

    /// (Phase 2) CAdES-B-B detached CMS over an arbitrary file.
    Cms {
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[command(flatten)]
        pin: PinSource,
        #[command(flatten)]
        opts: SignOpts,
    },

    /// (Phase 3) PAdES-B-B signature embedded in a PDF.
    Pdf {
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        location: Option<String>,
        #[arg(long)]
        contact_info: Option<String>,
        #[arg(long)]
        allow_resign: bool,
        /// Bounding box for a visible "TEST"-label signature
        /// appearance. Format: "llx,lly,urx,ury" in PDF points
        /// (1pt = 1/72 inch). Default: invisible.
        #[arg(long)]
        visible_rect: Option<String>,
        /// Page (1-based) for the visible appearance. Default: 1.
        #[arg(long, default_value_t = 1)]
        visible_page: usize,
        #[command(flatten)]
        pin: PinSource,
        #[command(flatten)]
        opts: SignOpts,
    },

    /// (Phase 4) XAdES-B-B XML signature.
    Xml {
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
        #[arg(long, default_value = "enveloped")]
        mode: String,
        #[command(flatten)]
        pin: PinSource,
        #[command(flatten)]
        opts: SignOpts,
    },

    /// (Phase 9) Verify a previously signed artifact. No card needed.
    #[command(subcommand)]
    Verify(VerifyCmd),
}

#[derive(Subcommand, Debug)]
enum VerifyCmd {
    /// Verify a detached CMS/CAdES signature (`.p7s`) against the
    /// content file that was signed.
    Cms {
        /// Detached CMS (.p7s) file.
        #[arg(long)]
        r#in: PathBuf,
        /// Content file that the signature covers.
        #[arg(long)]
        content: PathBuf,
        /// Trust-root certificate (PEM or DER) to anchor chain
        /// verification.
        #[arg(long)]
        ca_file: PathBuf,
        #[command(flatten)]
        opts: VerifyArgs,
    },
    /// Verify a PAdES-signed PDF.
    Pdf {
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        ca_file: PathBuf,
        #[command(flatten)]
        opts: VerifyArgs,
    },
    /// Verify a XAdES-signed XML document.
    Xml {
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        ca_file: PathBuf,
        #[command(flatten)]
        opts: VerifyArgs,
    },
}

#[derive(clap::Args, Debug, Clone)]
struct VerifyArgs {
    /// Accept any embedded TimeStampToken whose TSA cert chain is
    /// internally consistent, even if the TSA root isn't in
    /// --ca-file. Failure to anchor becomes a warning instead of a
    /// hard verification failure. Default: strict (TSA cert must
    /// chain to --ca-file).
    #[arg(long)]
    cert_internal: bool,
    /// Evaluate time-relative checks as if "now" were this point in
    /// time. Format: ISO 8601 UTC, e.g. 2026-06-01T15:00:00Z. Use
    /// when verifying a signature whose cert is expired *now* but
    /// was valid at the embedded signingTime.
    #[arg(long)]
    validation_time: Option<String>,
    /// Emit the verdict as JSON instead of the default human-readable
    /// pretty output. Schema mirrors the public VerifyReport struct.
    #[arg(long)]
    json: bool,
}

/// Parse "YYYY-MM-DDTHH:MM:SSZ" into SystemTime (UTC). Helper for
/// the --validation-time CLI flag.
fn parse_iso8601_utc(s: &str) -> firma_cr_core::Result<std::time::SystemTime> {
    let bad = |reason: &str| {
        firma_cr_core::Error::InvalidArg(format!(
            "--validation-time {s:?}: {reason}"
        ))
    };
    if s.len() != 20 || &s[19..] != "Z" {
        return Err(bad("expected YYYY-MM-DDTHH:MM:SSZ"));
    }
    let y: i32 = s[0..4].parse().map_err(|_| bad("bad year"))?;
    let mo: u32 = s[5..7].parse().map_err(|_| bad("bad month"))?;
    let d: u32 = s[8..10].parse().map_err(|_| bad("bad day"))?;
    let h: u32 = s[11..13].parse().map_err(|_| bad("bad hour"))?;
    let mi: u32 = s[14..16].parse().map_err(|_| bad("bad minute"))?;
    let se: u32 = s[17..19].parse().map_err(|_| bad("bad second"))?;
    // Day-count from epoch (1970-01-01).
    let mut days: i64 = 0;
    for yy in 1970..y {
        let leap = (yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0;
        days += if leap { 366 } else { 365 };
    }
    let leap_year = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays: [u32; 12] = [
        31,
        if leap_year { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    for m in 1..mo {
        days += mdays[(m - 1) as usize] as i64;
    }
    days += (d - 1) as i64;
    let secs =
        days * 86_400 + h as i64 * 3600 + mi as i64 * 60 + se as i64;
    if secs < 0 {
        return Err(bad("pre-epoch dates not supported"));
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

#[derive(clap::Args, Debug)]
struct PinSource {
    /// PIN typed inline. Visible via `/proc/<pid>/cmdline` — testing only.
    #[arg(long, group = "pin_source")]
    pin: Option<String>,
    /// Read PIN from the named environment variable.
    #[arg(long, group = "pin_source")]
    pin_env: Option<String>,
    /// Read PIN from a file (first line, trimmed).
    #[arg(long, group = "pin_source")]
    pin_file: Option<PathBuf>,
    /// Prompt for PIN interactively.
    #[arg(long, group = "pin_source")]
    pin_prompt: bool,
}

#[derive(clap::Args, Debug)]
struct SignOpts {
    /// Hash algorithm for the signature (sha256 | sha384 | sha512).
    #[arg(long, default_value = "sha256")]
    digest: String,
    /// Include intermediate cert chain in the signature certificates.
    #[arg(long)]
    include_chain: bool,
    /// Profile depth: B (baseline) | T (+timestamp) | LT (+revocation)
    /// | LTA (+archive timestamp).
    #[arg(long, default_value = "B")]
    profile: String,
    /// Time-Stamp Authority URL (required for -T / -LT / -LTA).
    #[arg(long)]
    tsa_url: Option<String>,
    /// OCSP responder URL override (default: AIA extension from cert).
    #[arg(long)]
    ocsp_url: Option<String>,
    /// CRL distribution-point URL override (default: CRLDP extension from cert).
    #[arg(long)]
    crl_url: Option<String>,
    /// Send an OCSP nonce but accept responses that omit it (default:
    /// strict — responder must echo the nonce per RFC 6960 §4.4.1).
    /// Required for some public responders (incl. BCCR's) that don't
    /// support the nonce extension.
    #[arg(long)]
    ocsp_nonce_optional: bool,
}

impl PinSource {
    fn resolve(&self) -> firma_cr_core::Result<String> {
        if let Some(p) = &self.pin {
            return Ok(p.clone());
        }
        if let Some(var) = &self.pin_env {
            return std::env::var(var).map_err(|_| {
                firma_cr_core::Error::InvalidArg(format!(
                    "env var {var} (--pin-env) is not set"
                ))
            });
        }
        if let Some(path) = &self.pin_file {
            let s = std::fs::read_to_string(path)?;
            return Ok(s.lines().next().unwrap_or("").trim().to_string());
        }
        if self.pin_prompt {
            return rpassword::prompt_password("PIN: ").map_err(|e| {
                firma_cr_core::Error::InvalidArg(format!("PIN prompt failed: {e}"))
            });
        }
        Err(firma_cr_core::Error::InvalidArg(
            "no PIN supplied — use --pin / --pin-env / --pin-file / --pin-prompt".into(),
        ))
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or("firma_cr_core=info"))
        .format_timestamp_millis()
        .init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Parse a "llx,lly,urx,ury" rect string for --visible-rect.
fn parse_visible_rect(s: &str) -> firma_cr_core::Result<(f32, f32, f32, f32)> {
    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    if parts.len() != 4 {
        return Err(firma_cr_core::Error::InvalidArg(
            "--visible-rect expects \"llx,lly,urx,ury\"".into(),
        ));
    }
    let mut nums = [0.0f32; 4];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p.parse::<f32>().map_err(|_| {
            firma_cr_core::Error::InvalidArg(format!(
                "--visible-rect component {p:?} is not a number"
            ))
        })?;
    }
    Ok((nums[0], nums[1], nums[2], nums[3]))
}

/// Resolve OCSP + CRL URLs (CLI overrides first, then cert
/// extensions) and fetch revocation data for `cert`. The issuer cert
/// must be present in `chain`. Returns `None` if no revocation
/// sources are configured.
fn fetch_revocation(
    cert: &SignerCert,
    chain: &[&SignerCert],
    sign_opts: &SignOpts,
) -> firma_cr_core::Result<Option<firma_cr_core::revocation::RevocationData>> {
    use firma_cr_core::revocation::{aia, fetch_crl, fetch_ocsp, ocsp, RevocationData};

    let issuer = chain
        .iter()
        .find(|c| c.parsed.tbs_certificate.subject == cert.parsed.tbs_certificate.issuer)
        .copied()
        .ok_or_else(|| {
            firma_cr_core::Error::InvalidArg(
                "issuer cert not present in --include-chain bundle (required for -LT)"
                    .into(),
            )
        })?;

    let ocsp_url = sign_opts.ocsp_url.clone().or_else(|| aia::ocsp_urls(cert).into_iter().next());
    let crl_url = sign_opts.crl_url.clone().or_else(|| aia::crl_urls(cert).into_iter().next());

    let mut data = RevocationData::default();
    if let Some(url) = &ocsp_url {
        let nonce: [u8; 16] = rand_nonce();
        let req = ocsp::build_request(cert, issuer, Some(&nonce))?;
        let resp = fetch_ocsp(url, &req)?;
        let parsed = ocsp::parse_response(&resp, cert, issuer)?;
        ocsp::check_nonce(&parsed, &nonce, !sign_opts.ocsp_nonce_optional)?;
        data.ocsp_responses.push(resp);
    }
    if let Some(url) = &crl_url {
        data.crls.push(fetch_crl(url)?);
    }
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

fn rand_nonce() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut out = [0u8; 16];
    let bytes = n.to_be_bytes();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

/// Build a closure that calls our TSA module for one timestamp,
/// usable as the `with_timestamp` callback on any of the builders.
fn make_tsa_fn(
    tsa_url: String,
    digest: HashAlgo,
) -> impl Fn(&[u8]) -> firma_cr_core::Result<Vec<u8>> + 'static {
    move |sig: &[u8]| {
        let req = firma_cr_core::tsa::TimestampRequest::new(sig, digest);
        let req_der = req.to_der()?;
        let token = firma_cr_core::tsa::request_token(&tsa_url, &req_der)?;
        Ok(token.token_der)
    }
}

fn run(cli: Cli) -> firma_cr_core::Result<()> {
    // Verify subcommands don't need card access — handle first.
    if let Cmd::Verify(v) = &cli.cmd {
        return run_verify(v);
    }

    let mut client = CardClient::open(&cli.module, cli.slot)?;

    let cert = match &cli.cert_file {
        Some(path) => SignerCert::from_file(path)?,
        None => {
            let der = client.read_certificate()?;
            SignerCert::from_der(der)?
        }
    };

    let chain: Vec<SignerCert> = match &cli.include_chain {
        Some(path) => SignerCert::load_chain_from_pem(path)?,
        None => {
            // No bundle supplied — try the cert's AIA extension. The
            // BCCR-issued leaves point at SINPE for the intermediate
            // chain; auto-fetching saves the user the manual
            // download. Best-effort: a fetch failure isn't fatal.
            match firma_cr_core::revocation::aia::fetch_issuer_chain(&cert, 6) {
                Ok(c) if !c.is_empty() => {
                    log::info!(
                        "aia: auto-fetched {} cert(s) via id-ad-caIssuers",
                        c.len()
                    );
                    c
                }
                Ok(_) => Vec::new(),
                Err(e) => {
                    log::warn!("aia: chain auto-fetch failed: {e}");
                    Vec::new()
                }
            }
        }
    };
    let chain_refs: Vec<&SignerCert> = chain.iter().collect();

    match cli.cmd {
        Cmd::Verify(_) => unreachable!("handled above"),
        Cmd::Info => cmd_info(&client, &cert),
        Cmd::Cms { input, output, pin, opts } => {
            let algo = HashAlgo::parse(&opts.digest).ok_or_else(|| {
                firma_cr_core::Error::InvalidArg(format!("unknown digest: {}", opts.digest))
            })?;
            client.login(&pin.resolve()?)?;
            let key = client.read_signing_key()?;
            let data = std::fs::read(&input)?;
            log::info!(
                "cades: signing {} ({} bytes) with {} → {}",
                input.display(),
                data.len(),
                algo.name(),
                output.display(),
            );
            let signer = CardSigner::new(&client, &key);
            let mut builder = CadesBuilder::new(&data, algo, &cert);
            if !chain_refs.is_empty() {
                builder = builder.include_chain(chain_refs.clone());
            }
            let profile_upper = opts.profile.to_ascii_uppercase();
            if profile_upper != "B" {
                let url = opts.tsa_url.clone().ok_or_else(|| firma_cr_core::Error::InvalidArg(
                    "--profile T/LT/LTA requires --tsa-url".into()))?;
                builder = builder.with_timestamp(make_tsa_fn(url, algo));
            }
            if profile_upper == "LT" || profile_upper == "LTA" {
                if let Some(rev) = fetch_revocation(&cert, &chain_refs, &opts)? {
                    builder = builder.with_revocation_data(rev);
                }
            }
            if profile_upper == "LTA" {
                let url = opts.tsa_url.clone().ok_or_else(|| firma_cr_core::Error::InvalidArg(
                    "--profile LTA requires --tsa-url".into()))?;
                builder = builder.with_archive_timestamp(make_tsa_fn(url, algo));
            }
            let cms_der = builder.build(&signer)?;
            std::fs::write(&output, &cms_der)?;
            println!(
                "wrote {} ({} bytes detached CMS, CAdES-B-B over {})",
                output.display(),
                cms_der.len(),
                input.display(),
            );
            Ok(())
        }
        Cmd::Pdf { input, output, reason, location, contact_info, allow_resign, visible_rect, visible_page, pin, opts } => {
            let algo = HashAlgo::parse(&opts.digest).ok_or_else(|| {
                firma_cr_core::Error::InvalidArg(format!("unknown digest: {}", opts.digest))
            })?;
            client.login(&pin.resolve()?)?;
            let key = client.read_signing_key()?;
            let pdf_bytes = std::fs::read(&input)?;
            log::info!(
                "pades: signing {} ({} bytes) → {}",
                input.display(),
                pdf_bytes.len(),
                output.display(),
            );
            let signer = CardSigner::new(&client, &key);
            let timestamp_fn: Option<firma_cr_core::cades::TimestampFn> =
                if opts.profile.to_ascii_uppercase() != "B" {
                    let url = opts.tsa_url.clone().ok_or_else(|| firma_cr_core::Error::InvalidArg(
                        "--profile T/LT/LTA requires --tsa-url".into()))?;
                    Some(Box::new(make_tsa_fn(url, algo)))
                } else {
                    None
                };
            let visible = visible_rect
                .as_deref()
                .map(parse_visible_rect)
                .transpose()?
                .map(|rect| firma_cr_core::pades::VisibleAppearance {
                    rect,
                    page: visible_page,
                    label: "TEST".to_string(),
                });
            let profile_upper = opts.profile.to_ascii_uppercase();
            let pdf_revocation = if profile_upper == "LT" || profile_upper == "LTA" {
                fetch_revocation(&cert, &chain_refs, &opts)?
            } else {
                None
            };
            let signed = firma_cr_core::pades::sign_pdf(
                &pdf_bytes,
                &cert,
                &chain_refs,
                algo,
                reason.as_deref(),
                location.as_deref(),
                contact_info.as_deref(),
                std::time::SystemTime::now(),
                &signer,
                timestamp_fn,
                visible,
                allow_resign,
                pdf_revocation.as_ref(),
            )?;
            std::fs::write(&output, &signed)?;
            println!(
                "wrote {} ({} bytes signed PDF)",
                output.display(),
                signed.len(),
            );
            Ok(())
        }
        Cmd::Xml { input, output, mode, pin, opts } => {
            if mode != "enveloped" {
                return Err(firma_cr_core::Error::InvalidArg(format!(
                    "xml --mode={mode} not yet implemented; only `enveloped` lands in Phase 4"
                )));
            }
            let algo = HashAlgo::parse(&opts.digest).ok_or_else(|| {
                firma_cr_core::Error::InvalidArg(format!("unknown digest: {}", opts.digest))
            })?;
            client.login(&pin.resolve()?)?;
            let key = client.read_signing_key()?;
            let xml_bytes = std::fs::read(&input)?;
            log::info!(
                "xades: signing {} ({} bytes) → {}",
                input.display(),
                xml_bytes.len(),
                output.display(),
            );
            let signer = CardSigner::new(&client, &key);
            let mut xb = firma_cr_core::xades::XadesBuilder::new(&xml_bytes, algo, &cert);
            if !chain_refs.is_empty() {
                xb = xb.include_chain(chain_refs.clone());
            }
            let profile_upper = opts.profile.to_ascii_uppercase();
            if profile_upper != "B" {
                let url = opts.tsa_url.clone().ok_or_else(|| firma_cr_core::Error::InvalidArg(
                    "--profile T/LT/LTA requires --tsa-url".into()))?;
                xb = xb.with_timestamp(make_tsa_fn(url, algo));
            }
            if profile_upper == "LT" || profile_upper == "LTA" {
                if let Some(rev) = fetch_revocation(&cert, &chain_refs, &opts)? {
                    xb = xb.with_revocation_data(rev);
                }
            }
            if profile_upper == "LTA" {
                let url = opts.tsa_url.clone().ok_or_else(|| firma_cr_core::Error::InvalidArg(
                    "--profile LTA requires --tsa-url".into()))?;
                xb = xb.with_archive_timestamp(make_tsa_fn(url, algo));
            }
            let signed = xb.build_enveloped(&signer)?;
            std::fs::write(&output, &signed)?;
            println!(
                "wrote {} ({} bytes signed XML, XAdES-B-B enveloped)",
                output.display(),
                signed.len(),
            );
            Ok(())
        }
    }
}

fn run_verify(cmd: &VerifyCmd) -> firma_cr_core::Result<()> {
    use firma_cr_core::verify::{self, VerifyOptions};
    let (input_path, ca_path, vopts) = match cmd {
        VerifyCmd::Cms { r#in, ca_file, opts, .. } => (r#in, ca_file, opts),
        VerifyCmd::Pdf { r#in, ca_file, opts } => (r#in, ca_file, opts),
        VerifyCmd::Xml { r#in, ca_file, opts } => (r#in, ca_file, opts),
    };
    let trust_root = SignerCert::from_file(ca_path)?;
    let validation_time = match &vopts.validation_time {
        Some(s) => Some(parse_iso8601_utc(s)?),
        None => None,
    };
    let options = VerifyOptions {
        cert_internal: vopts.cert_internal,
        validation_time,
    };
    let report = match cmd {
        VerifyCmd::Cms { content, .. } => {
            let p7s = std::fs::read(input_path)?;
            let content_bytes = std::fs::read(content)?;
            verify::cms::verify_detached(&p7s, &content_bytes, &trust_root, options)?
        }
        VerifyCmd::Pdf { .. } => {
            let pdf = std::fs::read(input_path)?;
            verify::pades::verify_pdf(&pdf, &trust_root, options)?
        }
        VerifyCmd::Xml { .. } => {
            let xml = std::fs::read(input_path)?;
            verify::xades::verify_xml(&xml, &trust_root, options)?
        }
    };
    if vopts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| {
                firma_cr_core::Error::InvalidArg(format!("JSON serialize: {e}"))
            })?
        );
    } else {
        print!("{}", report.pretty());
    }
    if report.ok {
        Ok(())
    } else {
        Err(firma_cr_core::Error::InvalidArg(
            "verification failed (see verdict above)".into(),
        ))
    }
}

fn cmd_info(client: &CardClient, cert: &SignerCert) -> firma_cr_core::Result<()> {
    println!("--- module + token ---");
    println!("{}", client.info()?);
    println!();
    println!("--- signer certificate ---");
    println!("subject:    {}", cert.subject_string());
    println!("issuer:     {}", cert.issuer_string());
    let (nb, na) = cert.validity_window();
    println!("not before: {nb}");
    println!("not after:  {na}");
    println!("serial:     {}", cert.serial_hex());
    println!("DER bytes:  {}", cert.der.len());
    let sha256 = cert.cert_digest(HashAlgo::Sha256);
    println!("sha256(cert): {}", hex::encode(&sha256));
    Ok(())
}
