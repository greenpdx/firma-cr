//! Deep card probe. Talks PC/SC directly (no PKCS#11 indirection) to pull
//! every byte we can read off a BCCR card without risking PIN lockout.
//! Output is a JSON report suitable for replay / offline analysis.
//!
//! Strategy:
//!   1. Connect to reader, log ATR.
//!   2. SELECT MF (3F00).
//!   3. SELECT EF.DIR (2F00) -> READ BINARY all -> parse PKCS#15 app list.
//!   4. For each application AID found, SELECT it and probe well-known
//!      PKCS#15 file IDs (ODF, TokenInfo, AOD, PrKDF, CDF, PuKDF).
//!   5. If EF.DIR was empty, brute-force a list of known IDProtect AIDs
//!      so JCOP3 cards also surface useful data.
//!   6. With --with-pin: do a SINGLE VERIFY attempt, then re-probe to
//!      capture authenticated reads (typically the cert content).
//!
//! Every APDU exchange is recorded in the output with the response SW
//! and an annotation. Nothing is interpreted beyond what we already
//! understand — raw hex goes to the report so the developer can finish
//! offline.

use anyhow::{anyhow, Context, Result};
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Default)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub generated_at: String,
    pub reader_name: String,
    pub atr_hex: String,
    pub atr_matches_known: Option<String>,
    pub mf_selected: bool,
    pub ef_dir: Option<EfBytes>,
    pub parsed_apps: Vec<ParsedApp>,
    /// Files discovered by following EF.ODF (round 2 probe).
    pub odf_targets: Vec<OdfTarget>,
    /// Auto-extracted from EF.AOD; used by --with-pin VERIFY.
    pub discovered_pin_ref: Option<u8>,
    /// Auto-extracted from EF.AOD PinAttributes.storedLength. The PIN
    /// data field is padded to this many bytes for VERIFY.
    pub discovered_pin_stored_length: Option<u8>,
    /// Auto-extracted from EF.AOD PinAttributes.padChar if present.
    pub discovered_pin_pad_char: Option<u8>,
    /// Cert file paths discovered in EF.CDF.
    pub discovered_cert_paths: Vec<String>,
    /// TR-03110 SecurityInfos files (EF.CardAccess 011C, EF.CardSecurity
    /// 011D) read in search of the Chip Authentication public key.
    pub securityinfos: Vec<SecurityInfoFile>,
    pub apdus: Vec<ApduRecord>,
    pub pin_probe: Option<PinProbeResult>,
    pub notes: Vec<String>,
}

#[derive(Serialize)]
pub struct SecurityInfoFile {
    pub name: String,
    pub fid_hex: String,
    pub select_sw: String,
    pub bytes_hex: Option<String>,
    pub bytes_len: usize,
    /// True if the bytes contain the TR-03110 id-PK OID prefix
    /// (0.4.0.127.0.7.2.2.1) — i.e. a ChipAuthenticationPublicKeyInfo.
    pub contains_ca_pubkey: bool,
}

#[derive(Serialize)]
pub struct OdfTarget {
    /// Context-tag from EF.ODF: 0=PrKDF, 1=PuKDF, 4=CDF, 7=DODF, 8=AOD, etc.
    pub odf_tag: u8,
    pub odf_tag_name: String,
    pub fid_hex: String,
    pub select_sw: String,
    pub bytes_hex: Option<String>,
    pub bytes_len: usize,
}

#[derive(Serialize)]
pub struct EfBytes {
    pub fid_hex: String,
    pub bytes_hex: String,
    pub bytes_len: usize,
}

#[derive(Serialize)]
pub struct ParsedApp {
    pub aid_hex: String,
    pub label: Option<String>,
    pub ddo_hex: Option<String>,
    pub probes: Vec<AppletProbe>,
}

#[derive(Serialize)]
pub struct AppletProbe {
    pub fid_hex: String,
    pub fid_name: String,
    pub select_sw: String,
    pub bytes_hex: Option<String>,
    pub bytes_len: usize,
}

#[derive(Serialize)]
pub struct ApduRecord {
    pub seq: usize,
    pub annotation: String,
    pub command_hex: String,
    pub response_hex: String,
    pub sw_hex: String,
    pub data_len: usize,
}

#[derive(Serialize)]
pub struct PinProbeResult {
    pub attempted_after_aid_hex: String,
    pub verify_sw: String,
    pub success: bool,
    pub cert_after_login: Option<EfBytes>,
    pub notes: Vec<String>,
}

const WELL_KNOWN_FIDS: &[(u16, &str)] = &[
    (0x5031, "EF.ODF"),
    (0x5032, "EF.TokenInfo"),
    (0x5033, "EF.UnusedSpace"),
    (0x4401, "EF.AOD (common location)"),
    (0x4404, "EF.PrKDF (common location)"),
    (0x4402, "EF.PuKDF (common location)"),
    (0x4403, "EF.CDF  (common location)"),
];

/// IDProtect AID candidates worth trying when EF.DIR is empty / absent.
/// Sourced from public OpenSC issues + a byte sequence we observed in
/// libt_ias.so .rodata.
const FALLBACK_AIDS: &[&[u8]] = &[
    &[0xA0,0x00,0x00,0x00,0x18,0x43,0x4D,0x00],
    &[0xA0,0x00,0x00,0x00,0x18,0x43,0x50,0x49,0x49,0x00,0x00,0x01],
    &[0xA0,0x00,0x00,0x00,0x18,0x80,0x00,0x00,0x03,0x0E,0x00,0x00],
    &[0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE],
];

pub struct Prober {
    card: Card,
    report: ProbeReport,
    seq: usize,
}

impl Prober {
    pub fn connect(reader_index: usize) -> Result<Self> {
        let ctx = match PcscContext::establish(Scope::User) {
            Ok(c) => c,
            Err(pcsc::Error::ServiceStopped) | Err(pcsc::Error::NoService) => {
                return Err(anyhow!(
                    "PC/SC daemon (pcscd) is not running. Start it: sudo systemctl start pcscd"
                ));
            }
            Err(e) if matches!(format!("{:?}", e).as_str(), s if s.contains("SecurityViolation")) => {
                return Err(anyhow!(
                    "pcscd denied access (polkit SecurityViolation). \
                     Run ./scripts/00-prereqs.sh to install the polkit rule, \
                     then log out and log back in so the plugdev group takes effect."
                ));
            }
            Err(e) => return Err(anyhow!("SCardEstablishContext failed: {:?}", e)),
        };
        let mut readers_buf = [0u8; 4096];
        let readers: Vec<_> = ctx.list_readers(&mut readers_buf)
            .context("SCardListReaders")?
            .map(|c| c.to_owned())
            .collect();
        if readers.is_empty() {
            return Err(anyhow!("no PC/SC readers present"));
        }
        let reader = readers.get(reader_index)
            .ok_or_else(|| anyhow!("reader index {} out of range ({})", reader_index, readers.len()))?;
        log::info!("probe: connecting to reader {:?}", reader);
        let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)
            .context("SCardConnect (is a card inserted?)")?;
        let mut names_buf = [0u8; 256];
        let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
        let status = card.status2(&mut names_buf, &mut atr_buf).context("SCardStatus")?;
        let atr_hex = hex::encode(status.atr());
        log::info!("probe: ATR = {}", atr_hex);

        Ok(Self {
            card,
            seq: 0,
            report: ProbeReport {
                schema_version: 1,
                generated_at: chrono_like_now(),
                reader_name: reader.to_string_lossy().into_owned(),
                atr_hex,
                ..Default::default()
            },
        })
    }

    fn apdu(&mut self, annotation: &str, cmd: &[u8]) -> Result<(Vec<u8>, u16)> {
        self.seq += 1;
        let mut resp = [0u8; 4096];
        let rsp = self.card.transmit(cmd, &mut resp).context("SCardTransmit")?;
        if rsp.len() < 2 {
            return Err(anyhow!("response shorter than 2 bytes (no SW)"));
        }
        let (data, sw) = rsp.split_at(rsp.len() - 2);
        let sw_val = ((sw[0] as u16) << 8) | sw[1] as u16;
        // PIN bytes are redacted in both the live log and the recorded report.
        let cmd_for_log = redact_apdu_for_log(cmd);
        log::debug!(
            "probe APDU #{} {}: >> {} ; << {} SW={:04X}",
            self.seq, annotation, cmd_for_log, hex::encode(data), sw_val
        );
        self.report.apdus.push(ApduRecord {
            seq: self.seq,
            annotation: annotation.to_string(),
            command_hex: cmd_for_log,
            response_hex: hex::encode(data),
            sw_hex: format!("{:04X}", sw_val),
            data_len: data.len(),
        });
        Ok((data.to_vec(), sw_val))
    }

    fn select_mf(&mut self) -> Result<bool> {
        let cmd = &[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00];
        let (_, sw) = self.apdu("SELECT MF", cmd)?;
        Ok(sw == 0x9000)
    }

    fn select_fid(&mut self, fid: u16, p1: u8) -> Result<u16> {
        let cmd = [0x00, 0xA4, p1, 0x00, 0x02, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let (_, sw) = self.apdu(&format!("SELECT FID {:04X} (P1={:02X})", fid, p1), &cmd)?;
        Ok(sw)
    }

    fn select_aid(&mut self, aid: &[u8]) -> Result<u16> {
        let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        cmd.extend_from_slice(aid);
        let (_, sw) = self.apdu(&format!("SELECT AID {}", hex::encode(aid)), &cmd)?;
        Ok(sw)
    }

    fn read_binary_all(&mut self, label: &str) -> Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let mut offset: u16 = 0;
        loop {
            let cmd = [0x00, 0xB0, ((offset >> 8) & 0x7F) as u8, (offset & 0xFF) as u8, 0xFF];
            let (data, sw) = self.apdu(&format!("READ BINARY {} off={}", label, offset), &cmd)?;
            match sw {
                0x9000 => {
                    out.extend_from_slice(&data);
                    if data.len() < 0xFF {
                        return Ok(Some(out));
                    }
                    offset = offset.saturating_add(data.len() as u16);
                }
                0x6282 => {
                    out.extend_from_slice(&data);
                    return Ok(Some(out));
                }
                0x6B00 => return Ok(if out.is_empty() { None } else { Some(out) }),
                _ => {
                    log::debug!("probe: READ BINARY {} terminated with SW={:04X}", label, sw);
                    return Ok(if out.is_empty() { None } else { Some(out) });
                }
            }
            if out.len() > 16384 {
                self.report.notes.push(format!("{}: capped read at 16 KiB", label));
                return Ok(Some(out));
            }
        }
    }

    pub fn run_unauthenticated(&mut self) -> Result<()> {
        self.report.mf_selected = self.select_mf()?;
        if !self.report.mf_selected {
            self.report.notes.push("SELECT MF failed; card may not expose a standard 3F00 root.".into());
        }

        // Read the TR-03110 SecurityInfos files looking for the chip's
        // static Chip-Authentication public key (needed for our ECDH).
        self.probe_securityinfos()?;
        // Re-select MF so the rest of the walk starts from a known state.
        self.select_mf()?;

        if self.select_fid(0x2F00, 0x02)? == 0x9000 {
            if let Some(bytes) = self.read_binary_all("EF.DIR")? {
                let parsed = parse_ef_dir(&bytes);
                self.report.ef_dir = Some(EfBytes {
                    fid_hex: "2F00".into(),
                    bytes_len: bytes.len(),
                    bytes_hex: hex::encode(&bytes),
                });
                for (aid, label, ddo) in parsed {
                    let probes = self.probe_application(&aid)?;
                    self.report.parsed_apps.push(ParsedApp {
                        aid_hex: hex::encode(&aid),
                        label,
                        ddo_hex: ddo.map(hex::encode),
                        probes,
                    });
                }
            }
        } else {
            self.report.notes.push("SELECT EF.DIR (2F00) failed; falling back to known-AID brute force.".into());
            for aid in FALLBACK_AIDS {
                let probes = self.probe_application(aid)?;
                if !probes.is_empty() {
                    self.report.parsed_apps.push(ParsedApp {
                        aid_hex: hex::encode(aid),
                        label: Some("(fallback candidate)".into()),
                        ddo_hex: None,
                        probes,
                    });
                }
            }
        }
        Ok(())
    }

    fn probe_application(&mut self, aid: &[u8]) -> Result<Vec<AppletProbe>> {
        let sw = self.select_aid(aid)?;
        if sw != 0x9000 {
            log::debug!("probe: SELECT AID {} failed with SW={:04X}, skipping", hex::encode(aid), sw);
            return Ok(vec![]);
        }
        let mut probes = Vec::new();
        let mut odf_bytes: Option<Vec<u8>> = None;
        for (fid, name) in WELL_KNOWN_FIDS {
            let sw = self.select_fid(*fid, 0x02)?;
            let bytes = if sw == 0x9000 {
                self.read_binary_all(name)?
            } else {
                None
            };
            if *fid == 0x5031 && bytes.is_some() {
                odf_bytes = bytes.clone();
            }
            probes.push(AppletProbe {
                fid_hex: format!("{:04X}", fid),
                fid_name: name.to_string(),
                select_sw: format!("{:04X}", sw),
                bytes_len: bytes.as_ref().map(|b| b.len()).unwrap_or(0),
                bytes_hex: bytes.as_ref().map(hex::encode),
            });
        }

        // If we got EF.ODF, follow its entries to discover the real
        // file IDs for EF.AOD / EF.PrKDF / EF.PuKDF / EF.CDF.
        if let Some(odf) = odf_bytes {
            self.follow_odf(&odf)?;
        }
        Ok(probes)
    }

    /// Read EF.CardAccess (011C) and EF.CardSecurity (011D) at the MF
    /// level. These TR-03110 SecurityInfos files are where a card
    /// publishes its Chip Authentication parameters and (in CardSecurity
    /// / DG14) the static CA public key we need for the ECDH.
    fn probe_securityinfos(&mut self) -> Result<()> {
        const FILES: &[(u16, &str)] = &[
            (0x011C, "EF.CardAccess"),
            (0x011D, "EF.CardSecurity"),
            (0x2F00, "EF.DIR (control)"),  // harmless re-read for cross-check
        ];
        // EF.CardAccess/CardSecurity live under the MF.
        self.select_mf()?;
        for (fid, name) in FILES {
            // Try child-EF select first (P1=02), then by-FID (P1=00).
            let mut sw = self.select_fid(*fid, 0x02)?;
            if sw != 0x9000 {
                sw = self.select_fid(*fid, 0x00)?;
            }
            let bytes = if sw == 0x9000 {
                self.read_binary_all(name)?
            } else {
                None
            };
            let contains = bytes.as_deref().map(contains_id_pk).unwrap_or(false);
            if contains {
                log::info!("probe: {} ({:04X}) CONTAINS a ChipAuthenticationPublicKeyInfo (id-PK)", name, fid);
            } else if bytes.is_some() {
                log::info!("probe: {} ({:04X}) read OK, {} bytes (no id-PK OID found)",
                    name, fid, bytes.as_ref().unwrap().len());
            } else {
                log::info!("probe: {} ({:04X}) not readable (SW={:04X})", name, fid, sw);
            }
            self.report.securityinfos.push(SecurityInfoFile {
                name: name.to_string(),
                fid_hex: format!("{:04X}", fid),
                select_sw: format!("{:04X}", sw),
                bytes_len: bytes.as_ref().map(|b| b.len()).unwrap_or(0),
                bytes_hex: bytes.as_ref().map(hex::encode),
                contains_ca_pubkey: contains,
            });
        }
        Ok(())
    }

    fn follow_odf(&mut self, odf_bytes: &[u8]) -> Result<()> {
        log::info!("probe: parsing EF.ODF ({} bytes) for path map", odf_bytes.len());
        let entries = parse_ef_odf(odf_bytes);
        log::info!("probe: EF.ODF lists {} directory entries", entries.len());

        let mut aod_bytes: Option<Vec<u8>> = None;
        let mut cdf_bytes: Option<Vec<u8>> = None;

        for (tag, fid) in entries {
            let name = odf_tag_name(tag);
            log::info!("probe: following ODF entry tag=[{}]={} -> FID {:04X}", tag, name, fid);
            let sw = self.select_fid(fid, 0x02)?;
            let bytes = if sw == 0x9000 {
                self.read_binary_all(&format!("{}@{:04X}", name, fid))?
            } else { None };
            if tag == 8 { aod_bytes = bytes.clone(); }
            if tag == 4 { cdf_bytes = bytes.clone(); }
            self.report.odf_targets.push(OdfTarget {
                odf_tag: tag,
                odf_tag_name: name.to_string(),
                fid_hex: format!("{:04X}", fid),
                select_sw: format!("{:04X}", sw),
                bytes_len: bytes.as_ref().map(|b| b.len()).unwrap_or(0),
                bytes_hex: bytes.as_ref().map(hex::encode),
            });
        }

        if let Some(b) = &aod_bytes {
            let attrs = extract_pin_attrs(b);
            log::info!(
                "probe: PIN attrs from EF.AOD — ref={:?} min={:?} stored={:?} max={:?} pad={:?}",
                attrs.reference, attrs.min_length, attrs.stored_length, attrs.max_length, attrs.pad_char,
            );
            self.report.discovered_pin_ref = attrs.reference;
            self.report.discovered_pin_stored_length = attrs.stored_length;
            self.report.discovered_pin_pad_char = attrs.pad_char;
            if attrs.reference.is_none() {
                self.report.notes.push("EF.AOD read but PIN reference not found".into());
            }
        }

        if let Some(b) = &cdf_bytes {
            let paths = extract_cdf_paths(b);
            for p in &paths {
                log::info!("probe: discovered cert path {}", hex::encode(p));
                self.report.discovered_cert_paths.push(hex::encode(p));
            }
        }

        Ok(())
    }

    pub fn run_with_pin(
        &mut self,
        pin: &str,
        pin_ref_override: Option<u8>,
        pad_byte_override: Option<u8>,
    ) -> Result<()> {
        log::warn!("probe: VERIFY PIN — single attempt, will abort on failure to protect the card");
        std::thread::sleep(Duration::from_secs(2));

        let app_aid = self
            .report
            .parsed_apps
            .iter()
            .find(|a| !a.probes.is_empty())
            .map(|a| hex::decode(&a.aid_hex).unwrap_or_default())
            .ok_or_else(|| anyhow!("no readable application discovered; run unauthenticated probe first"))?;
        let _ = self.select_aid(&app_aid)?;

        // CRITICAL safety: refuse to VERIFY unless we have a PIN reference
        // we trust. Last round we wasted a counter slot on a guess; never again.
        let pin_ref = match (pin_ref_override, self.report.discovered_pin_ref) {
            (Some(r), _) => {
                log::warn!("probe: using CLI-supplied --pin-ref 0x{:02X} (overriding discovered)", r);
                r
            }
            (None, Some(r)) => {
                log::info!("probe: using PIN reference 0x{:02X} discovered from EF.AOD", r);
                r
            }
            (None, None) => {
                self.report.pin_probe = Some(PinProbeResult {
                    attempted_after_aid_hex: hex::encode(&app_aid),
                    verify_sw: "(not attempted)".into(),
                    success: false,
                    cert_after_login: None,
                    notes: vec![
                        "ABORTED: no PIN reference discovered from EF.AOD and none supplied via --pin-ref.".into(),
                        "Refusing to VERIFY with a guess to protect your card's retry counter.".into(),
                    ],
                });
                return Ok(());
            }
        };

        // Build the PIN data field, optionally padded to storedLength.
        // Pad-byte priority: CLI override > EF.AOD padChar > default 0xFF.
        let stored_len = self.report.discovered_pin_stored_length.map(|x| x as usize);
        let pad_byte = pad_byte_override
            .or(self.report.discovered_pin_pad_char)
            .unwrap_or(0xFF);
        let mut pin_data: Vec<u8> = pin.as_bytes().to_vec();
        let target_len = stored_len.unwrap_or(pin_data.len());
        let mut padded = false;
        if pin_data.len() < target_len {
            pin_data.resize(target_len, pad_byte);
            padded = true;
        }
        log::info!(
            "probe: VERIFY data field len={} (PIN was {} chars, padded={} with 0x{:02X} to storedLength={:?})",
            pin_data.len(), pin.len(), padded, pad_byte, stored_len,
        );

        let mut cmd = vec![0x00, 0x20, 0x00, pin_ref];
        cmd.push(pin_data.len() as u8);
        cmd.extend_from_slice(&pin_data);
        let (_, sw) = self.apdu(&format!("VERIFY PIN ref={:02X}", pin_ref), &cmd)?;

        let result = if sw == 0x9000 {
            log::info!("probe: VERIFY ok, reading discovered certs");
            let cert = self.read_first_discovered_cert(&app_aid)?;
            PinProbeResult {
                attempted_after_aid_hex: hex::encode(&app_aid),
                verify_sw: format!("{:04X}", sw),
                success: true,
                cert_after_login: cert,
                notes: vec![format!("PIN reference used: 0x{:02X}", pin_ref)],
            }
        } else {
            let mut notes = vec![
                format!("VERIFY returned SW={:04X} using pin_ref=0x{:02X}", sw, pin_ref),
            ];
            if (sw & 0xFFF0) == 0x63C0 {
                notes.push(format!("PIN has {} attempts remaining (counter DECREMENTED)", sw & 0x000F));
            } else if sw == 0x6983 || sw == 0x6984 {
                notes.push("PIN appears locked. STOP. Do not retry.".into());
            } else if sw == 0x6982 {
                notes.push("SW=6982 'security status not satisfied' — usually a structural rejection that does NOT decrement the counter.".into());
            }
            log::error!("probe: VERIFY failed with SW={:04X}; aborting", sw);
            PinProbeResult {
                attempted_after_aid_hex: hex::encode(&app_aid),
                verify_sw: format!("{:04X}", sw),
                success: false,
                cert_after_login: None,
                notes,
            }
        };
        self.report.pin_probe = Some(result);
        Ok(())
    }

    fn read_first_discovered_cert(&mut self, _aid: &[u8]) -> Result<Option<EfBytes>> {
        // Parse FIDs out of the cert-path hex strings we collected from EF.CDF
        // and try each. First one that yields bytes wins.
        let paths: Vec<Vec<u8>> = self.report.discovered_cert_paths.iter()
            .filter_map(|s| hex::decode(s).ok())
            .collect();
        if paths.is_empty() {
            self.report.notes.push("no cert paths discovered in EF.CDF".into());
            return Ok(None);
        }
        for p in paths {
            if p.len() != 2 {
                log::debug!("probe: skipping non-2-byte cert path {}", hex::encode(&p));
                continue;
            }
            let fid = ((p[0] as u16) << 8) | p[1] as u16;
            if self.select_fid(fid, 0x02)? == 0x9000 {
                if let Some(bytes) = self.read_binary_all(&format!("Cert@{:04X}", fid))? {
                    log::info!("probe: cert read OK from {:04X} ({} bytes)", fid, bytes.len());
                    return Ok(Some(EfBytes {
                        fid_hex: format!("{:04X}", fid),
                        bytes_len: bytes.len(),
                        bytes_hex: hex::encode(&bytes),
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn finalize(mut self) -> ProbeReport {
        self.report.atr_matches_known = match_atr(&self.report.atr_hex);
        self.report
    }
}

fn match_atr(atr_hex: &str) -> Option<String> {
    let lower = atr_hex.to_lowercase();
    if lower.starts_with("3bdc00ff8091fe1fc38073c821") {
        return Some("JCOP4 / BCCR IDProtectXF".into());
    }
    if lower.starts_with("3bd518ff8191fe1fc38073c821") {
        return Some("ChipDoc Generic / BCCR (IAS-ECC, NXP chip)".into());
    }
    // Catch-all: the 73 c8 21 substring is the Athena/NXP marker.
    if lower.contains("73c821") {
        return Some("NXP/Athena (unrecognized ATR variant)".into());
    }
    None
}

/// Map ODF context-tag to PKCS#15 directory name (ISO/IEC 7816-15).
fn odf_tag_name(tag: u8) -> &'static str {
    match tag {
        0 => "EF.PrKDF (private keys)",
        1 => "EF.PuKDF (public keys)",
        2 => "EF.TrustedPubKeyDF",
        3 => "EF.SKDF (secret keys)",
        4 => "EF.CDF (certificates)",
        5 => "EF.TrustedCertDF",
        6 => "EF.UsefulCertDF",
        7 => "EF.DODF (data objects)",
        8 => "EF.AOD (auth objects / PINs)",
        _ => "(unknown ODF tag)",
    }
}

/// Parse EF.ODF into (context_tag, file_id) pairs.
/// Each entry: `AN LEN { 30 LEN { 04 02 <fid_hi> <fid_lo> } }`
/// where N is the context-tag identifying the directory class.
pub fn parse_ef_odf(bytes: &[u8]) -> Vec<(u8, u16)> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        // Skip zero padding.
        if rest[0] == 0x00 { rest = &rest[1..]; continue; }
        let (tag, body, next) = match read_tlv(rest) { Some(t) => t, None => break };
        rest = next;
        if tag & 0xF0 != 0xA0 { continue; }      // need context-class tag
        let class_tag = tag & 0x0F;
        // body is SEQUENCE { OCTET STRING fid }
        if let Some((_, seq_body, _)) = read_tlv(body) {
            if let Some((0x04, fid_bytes, _)) = read_tlv(seq_body) {
                if fid_bytes.len() == 2 {
                    let fid = ((fid_bytes[0] as u16) << 8) | fid_bytes[1] as u16;
                    out.push((class_tag, fid));
                }
            }
        }
    }
    out
}

/// Scan EF.AOD bytes for the first `[0] IMPLICIT pinReference` field.
/// In ASN.1: `80 01 XX` where XX is the PIN reference byte (0x00..0x7F typically).
/// This is heuristic but matches every PKCS#15 PIN object I've seen.
pub fn extract_pin_ref(bytes: &[u8]) -> Option<u8> {
    extract_pin_attrs(bytes).reference
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PinAttrs {
    pub reference: Option<u8>,
    pub min_length: Option<u8>,
    pub stored_length: Option<u8>,
    pub max_length: Option<u8>,
    pub pad_char: Option<u8>,
}

/// Parse the relevant fields of the first PKCS#15 PinAttributes record found
/// in EF.AOD. PinAttributes per ISO/IEC 7816-15:
///   SEQUENCE {
///     pinFlags        BIT STRING,
///     pinType         ENUMERATED,
///     minLength       INTEGER,
///     storedLength    INTEGER,
///     maxLength       INTEGER OPTIONAL,
///     pinReference    [0] IMPLICIT INTEGER OPTIONAL,
///     padChar         OCTET STRING SIZE(1) OPTIONAL,
///     ...
///   }
///
/// We use ordered heuristic scanning: find `[0] 01 XX` (the pinReference tag),
/// then look backwards for the three INTEGER size fields that precede it,
/// and forwards for `04 01 XX` (padChar) that follows.
pub fn extract_pin_attrs(bytes: &[u8]) -> PinAttrs {
    let mut out = PinAttrs::default();

    // Locate `80 01 XX` — the pinReference TLV.
    let mut ref_idx = None;
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == 0x80 && bytes[i + 1] == 0x01 {
            ref_idx = Some(i);
            out.reference = Some(bytes[i + 2]);
            break;
        }
    }

    // Walk backwards from ref_idx collecting up to three preceding `02 01 NN`
    // entries (maxLength, storedLength, minLength in reverse).
    if let Some(rpos) = ref_idx {
        let mut sizes: Vec<u8> = Vec::new();
        let mut j = rpos;
        while j >= 3 && sizes.len() < 3 {
            j -= 3;
            if bytes[j] == 0x02 && bytes[j + 1] == 0x01 {
                sizes.push(bytes[j + 2]);
            } else {
                break;
            }
        }
        // sizes is in reverse-walk order: [max?, stored, min].
        // Most decks emit min/stored/max so reading them in order:
        let mut it = sizes.iter().rev();
        out.min_length = it.next().copied();
        out.stored_length = it.next().copied();
        out.max_length = it.next().copied();
    }

    // padChar: `04 01 XX`, typically right after pinReference's region.
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == 0x04 && bytes[i + 1] == 0x01 {
            // Heuristic: skip random `04 01 XX` that aren't PIN-related;
            // accept the first one that follows the pinReference.
            if ref_idx.map_or(false, |r| i > r) {
                out.pad_char = Some(bytes[i + 2]);
                break;
            }
        }
    }
    out
}

/// Build a hex string of `cmd` that hides the PIN value when cmd is a
/// VERIFY APDU (CLA=00 INS=20). Header (CLA INS P1 P2 Lc) kept,
/// data replaced with `XX` of the same length.
pub fn redact_apdu_for_log(cmd: &[u8]) -> String {
    if cmd.len() >= 5 && cmd[0] == 0x00 && cmd[1] == 0x20 {
        let header = hex::encode(&cmd[..5]);
        let data_len = cmd.len() - 5;
        let red = "XX".repeat(data_len);
        format!("{}{}", header, red)
    } else {
        hex::encode(cmd)
    }
}

/// True if the bytes contain the TR-03110 `id-PK` OID prefix
/// (0.4.0.127.0.7.2.2.1), the marker of a ChipAuthenticationPublicKeyInfo.
/// Encoded as an OID the prefix appears as `04 00 7F 00 07 02 02 01`.
pub fn contains_id_pk(bytes: &[u8]) -> bool {
    const ID_PK: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01];
    bytes.windows(ID_PK.len()).any(|w| w == ID_PK)
}

/// Extract every `04 02 XXYY` (OCTET STRING of length 2) from EF.CDF.
/// Each is a candidate Path → cert file ID.
pub fn extract_cdf_paths(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i] == 0x04 && bytes[i + 1] == 0x02 {
            out.push(bytes[i + 2..i + 4].to_vec());
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

fn parse_ef_dir(bytes: &[u8]) -> Vec<(Vec<u8>, Option<String>, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest[0] != 0x61 { rest = &rest[1..]; continue; }
        let (_t, body, next) = match read_tlv(rest) { Some(t) => t, None => break };
        let mut aid = Vec::new();
        let mut label = None;
        let mut ddo = None;
        let mut r = body;
        while !r.is_empty() {
            let (tag, val, n) = match read_tlv(r) { Some(t) => t, None => break };
            match tag {
                0x4F => aid = val.to_vec(),
                0x50 => label = std::str::from_utf8(val).ok().map(str::to_owned),
                0x73 => ddo = Some(val.to_vec()),
                _ => {}
            }
            r = n;
        }
        if !aid.is_empty() { out.push((aid, label, ddo)); }
        rest = next;
    }
    out
}

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 { return None; }
    let tag = input[0];
    let (len, hdr) = if input[1] < 0x80 {
        (input[1] as usize, 2)
    } else {
        let n = (input[1] & 0x7F) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n { return None; }
        let mut v: usize = 0;
        for &b in &input[2..2+n] { v = (v << 8) | b as usize; }
        (v, 2 + n)
    };
    if input.len() < hdr + len { return None; }
    Some((tag, &input[hdr..hdr+len], &input[hdr+len..]))
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("unix_secs={}", secs)
}
