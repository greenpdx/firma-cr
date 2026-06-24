// SPDX-License-Identifier: GPL-3.0-or-later
//! The local `/dyn` HTTP server (axum 0.8) on `127.0.0.1:41231` — the
//! GAUDI-compatible surface that BCCR websites call (DESIGN.md, reports/29).
//! Wires the pure modules (`session`, `api`, `dyn_request`) and the card modules
//! (`token`, `sign`) behind the `/dyn/<action>` routes, with CORS.
//!
//! State is `Arc<Mutex<AppState>>`; handlers do their (synchronous) card work
//! under the lock with no await held, so the futures stay `Send`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, RawQuery, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use zeroize::Zeroizing;

use crate::agent::api::{CreateEnvResponse, CryptoshellBuildRequest, LoginRequest, LoginResponse, OperationType};
use crate::agent::dyn_request::DynRequest;
use crate::agent::session::EnvStore;
use crate::agent::sign::{build_sign, FileStore, SignedFile};
use crate::agent::token::TokenSession;

// --- abuse limits on the (CORS-open, localhost) /dyn surface -----------------
// The agent must stay callable by BCCR websites, so we don't authenticate; we
// instead cap the cheap-to-abuse paths. A malicious local page cannot make these
// limits looser, and they don't change the wire protocol.

/// Max failed `/dyn/login` attempts (process-wide) before a cooldown kicks in.
/// Slows a hostile page from burning the card's own (small) PIN retry counter or
/// using repeated logins as a denial-of-service against the cardholder.
const MAX_LOGIN_FAILS: u32 = 5;
/// Sliding window / cooldown for the login limiter.
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
/// Max bytes accepted by `cryptoshell_add_file` for one document (memory bound).
const MAX_UPLOAD_BYTES: usize = 32 << 20; // 32 MiB
/// Max staged documents per env.
const MAX_FILES_PER_ENV: usize = 32;
/// Max length of a caller-supplied file name.
const MAX_NAME_LEN: usize = 255;

/// The built-in default trust anchor for signature verification: the BCCR
/// national root (`CA RAÍZ NACIONAL - COSTA RICA v2`). This is the immutable
/// baseline — `set_ca` overlays an override on top of it and `reset_ca` returns
/// here; the embedded chain itself is never modified.
const DEFAULT_CA: &str = include_str!("bccr-ca.pem");

/// Failed-login tracker for the rate limiter. There is ONE physical card per
/// process, so this is tracked globally — NOT per env. (A per-env counter is
/// useless: `create_env` is unauthenticated and unlimited, so an attacker just
/// mints a fresh env per guess and never trips a per-env limit, while every
/// guess still burns the card's own small PIN-retry counter.)
struct LoginThrottle {
    fails: u32,
    first_fail: Instant,
}

/// The agent's shared card + session state. Public so an embedding app (Firma
/// CR) can construct ONE instance and share it between the HTTP handlers and its
/// own card commands — crfirma's `C_Initialize` is a process-global singleton,
/// so there must be exactly one card session per process.
pub struct AppState {
    envs: EnvStore,
    card: Option<TokenSession>,
    files: FileStore,
    signed: HashMap<String, Vec<SignedFile>>,
    module_path: PathBuf,
    login_throttle: Option<LoginThrottle>,
    /// Verification trust anchor override. `None` = use the embedded
    /// [`DEFAULT_CA`]; the embedded chain is never overwritten.
    ca_override: Option<String>,
}

impl AppState {
    pub fn new(module_path: PathBuf) -> Self {
        Self {
            envs: EnvStore::new(),
            card: None,
            files: FileStore::new(),
            signed: HashMap::new(),
            module_path,
            login_throttle: None,
            ca_override: None,
        }
    }

    /// The CA chain (PEM) currently used to verify: the override if one is set,
    /// else the built-in [`DEFAULT_CA`].
    pub fn active_ca(&self) -> &str {
        self.ca_override.as_deref().unwrap_or(DEFAULT_CA)
    }

    /// True when no override is set (the built-in default is in use).
    pub fn ca_is_default(&self) -> bool {
        self.ca_override.is_none()
    }

    /// Overlay a custom CA chain. Does NOT touch the embedded default.
    pub fn set_ca(&mut self, pem: String) {
        self.ca_override = Some(pem);
    }

    /// Drop the override → back to the embedded default.
    pub fn reset_ca(&mut self) {
        self.ca_override = None;
    }

    /// If logins are currently locked out (too many failures across the process),
    /// return the seconds left in the cooldown; otherwise `None`.
    fn login_lockout_remaining(&self) -> Option<u64> {
        let t = self.login_throttle.as_ref()?;
        if t.fails >= MAX_LOGIN_FAILS {
            let elapsed = t.first_fail.elapsed();
            if elapsed < LOGIN_WINDOW {
                return Some((LOGIN_WINDOW - elapsed).as_secs() + 1);
            }
        }
        None
    }

    /// Record a failed login (global), starting/refreshing the window.
    fn record_login_failure(&mut self) {
        let t = self
            .login_throttle
            .get_or_insert(LoginThrottle { fails: 0, first_fail: Instant::now() });
        if t.first_fail.elapsed() >= LOGIN_WINDOW {
            t.fails = 0;
            t.first_fail = Instant::now();
        }
        t.fails = t.fails.saturating_add(1);
    }

    /// Clear the failed-login counter (called on a successful login).
    fn clear_login_failures(&mut self) {
        self.login_throttle = None;
    }

    /// Connect the card if not already connected (idempotent — never opens a
    /// second `CardClient`). Returns the live session.
    pub fn ensure_card(&mut self) -> Result<&mut TokenSession, String> {
        if self.card.is_none() {
            self.card = Some(TokenSession::connect(&self.module_path).map_err(|e| e.to_string())?);
        }
        Ok(self.card.as_mut().unwrap())
    }

    pub fn card_mut(&mut self) -> Option<&mut TokenSession> {
        self.card.as_mut()
    }

    /// Drop the live card session so the next `ensure_card()` re-opens a fresh
    /// one. Self-recovery: when a card/Secure-Messaging op wedges the session
    /// (a stalled APDU, a cached Chip-Auth failure), the next request rebuilds
    /// the whole card stack (re-init, re-connect, re-Chip-Auth) instead of
    /// staying broken until the process restarts.
    pub fn reset_card(&mut self) {
        if self.card.take().is_some() {
            log::warn!("agent: dropping wedged card session; will re-open on next request");
        }
    }
}

/// `Arc<Mutex<AppState>>` — share one of these across the HTTP handlers and any
/// embedding app's commands.
pub type Shared = Arc<Mutex<AppState>>;

/// Build the `/dyn` router over an existing shared state.
pub fn app_with_state(state: Shared) -> Router {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    Router::new()
        .route("/dyn/create_env", get(create_env))
        .route("/dyn/connect", get(connect))
        .route("/dyn/get_token_info", get(get_token_info))
        .route("/dyn/begin_session", get(ok_true))
        .route("/dyn/activate_certificates", get(ok_true))
        .route("/dyn/login", get(login))
        .route("/dyn/get_certstore_certificates", get(get_certs))
        .route("/dyn/cryptoshell_add_file", post(add_file))
        .route("/dyn/cryptoshell_build", get(build))
        .route("/dyn/download", get(download))
        .route("/dyn/verify_pdf", post(verify_pdf))
        .route("/dyn/ca_info", get(ca_info))
        .route("/dyn/set_ca", post(set_ca))
        .route("/dyn/reset_ca", post(reset_ca))
        // Allow large PDFs/uploads (the JSON verify body + add_file's 32 MiB
        // cap). axum's default request-body limit is 2 MiB, too small here.
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .layer(cors)
        // Outermost: reject non-loopback Host headers. CORS lets *any web origin*
        // call us (BCCR sites must), but that plus a 127.0.0.1 bind leaves us open
        // to DNS rebinding — a public page rebinds its hostname to 127.0.0.1 and
        // drives the agent from the victim's browser. The browser still sends the
        // attacker's hostname in `Host:`, so allowlisting loopback Hosts blocks the
        // rebind while every legitimate caller (which connects to 127.0.0.1:<port>)
        // passes unaffected.
        .layer(middleware::from_fn(require_local_host))
        .with_state(state)
}

/// Reject any request whose `Host` header is not a loopback name/literal —
/// anti-DNS-rebinding for the localhost-bound `/dyn` server. See the comment at
/// the layer site in [`app_with_state`].
async fn require_local_host(req: Request, next: Next) -> Response {
    let allowed = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(host_is_local)
        .unwrap_or(false);
    if allowed {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "refusing non-loopback Host header\n").into_response()
    }
}

/// True iff `host` (a `Host:` header value, with optional port) names loopback:
/// `localhost`, `127.0.0.0/8`, or `[::1]`. Hostnames that resolve elsewhere — the
/// DNS-rebinding case — are rejected.
fn host_is_local(host: &str) -> bool {
    let h = host.trim();
    // Strip the optional port. IPv6 literals are bracketed: `[::1]` / `[::1]:port`.
    let name = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map(|(host, _port)| host).unwrap_or(h)
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Build the `/dyn` router with fresh state. `module_path` is the crfirma `.so`.
pub fn app(module_path: PathBuf) -> Router {
    app_with_state(Arc::new(Mutex::new(AppState::new(module_path))))
}

/// The address the `/dyn` server binds. Default `127.0.0.1:41231` (GAUDI's port,
/// where BCCR sites expect it); override with `FIRMA_CR_DYN_ADDR` (e.g.
/// `127.0.0.1:51231`) for a test instance alongside the real SCManager.
pub fn dyn_addr() -> String {
    std::env::var("FIRMA_CR_DYN_ADDR").unwrap_or_else(|_| "127.0.0.1:41231".to_string())
}

/// Bind and serve the `/dyn` API over an existing shared state.
pub async fn serve_with_state(state: Shared) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(dyn_addr()).await?;
    axum::serve(listener, app_with_state(state)).await
}

/// Bind and serve on `127.0.0.1:41231` with fresh state.
pub async fn serve(module_path: PathBuf) -> std::io::Result<()> {
    serve_with_state(Arc::new(Mutex::new(AppState::new(module_path)))).await
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Rebuild a [`DynRequest`] from the matched action + the raw query string.
fn parse(query: &Option<String>, action: &str) -> DynRequest {
    let target = match query {
        Some(q) => format!("/dyn/{action}?{q}"),
        None => format!("/dyn/{action}"),
    };
    DynRequest::parse(&target).unwrap_or(DynRequest {
        action: action.to_string(),
        env: None,
        params: Default::default(),
    })
}

fn bad(msg: impl ToString) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}
fn boom(msg: impl ToString) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()).into_response()
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// `POST /dyn/verify_pdf` — verify a PAdES PDF against a caller-supplied CA chain.
/// Body: JSON `{ "pdf_b64": "...", "ca_pem": "-----BEGIN CERTIFICATE-----\n..." }`.
/// No card/PIN — pure verification. Returns the `VerifyReport` as JSON. Mirrors
/// the Tauri `verify_pdf` command so the GUI works the same in the browser.
#[derive(serde::Deserialize)]
struct VerifyPdfReq {
    pdf_b64: String,
}

async fn verify_pdf(State(st): State<Shared>, Json(req): Json<VerifyPdfReq>) -> Response {
    use base64::Engine;
    let pdf = match base64::engine::general_purpose::STANDARD.decode(req.pdf_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => return bad(format!("decode PDF: {e}")),
    };
    let ca = match st.lock() {
        Ok(g) => g.active_ca().to_string(),
        Err(_) => return boom("state poisoned"),
    };
    let mut certs = crate::cert::SignerCert::chain_from_pem_str(&ca);
    if certs.is_empty() {
        return boom("active CA chain has no certificate");
    }
    // Trust anchor = the self-signed root; the rest (policy CAs) are extra
    // intermediates that bridge a leaf-only signature to the root.
    let root_pos = certs.iter().position(|c| c.is_self_signed()).unwrap_or(0);
    let root = certs.remove(root_pos);
    let opts = crate::verify::VerifyOptions { fetch_aia: true, ..Default::default() };
    match crate::verify::pades::verify_pdf_ex(&pdf, &root, &certs, opts) {
        Ok(report) => Json(report).into_response(),
        Err(e) => boom(format!("verify: {e}")),
    }
}

/// `POST /dyn/set_ca` — overlay a custom verification CA (PEM body). Validated
/// before acceptance; the embedded default is never touched. Returns ca_info.
async fn set_ca(State(st): State<Shared>, body: Bytes) -> Response {
    if body.len() > MAX_UPLOAD_BYTES {
        return bad("CA too large");
    }
    let pem = String::from_utf8_lossy(&body).into_owned();
    if crate::cert::SignerCert::chain_from_pem_str(&pem).is_empty() {
        return bad("CA chain has no parseable certificate");
    }
    match st.lock() {
        Ok(mut g) => {
            g.set_ca(pem);
            Json(ca_info_json(&g)).into_response()
        }
        Err(_) => boom("state poisoned"),
    }
}

/// `POST /dyn/reset_ca` — drop the override, back to the embedded default.
async fn reset_ca(State(st): State<Shared>) -> Response {
    match st.lock() {
        Ok(mut g) => {
            g.reset_ca();
            Json(ca_info_json(&g)).into_response()
        }
        Err(_) => boom("state poisoned"),
    }
}

/// `GET /dyn/ca_info` — describe the active verification CA (default vs override,
/// subject, SHA-256 fingerprint).
async fn ca_info(State(st): State<Shared>) -> Response {
    match st.lock() {
        Ok(g) => Json(ca_info_json(&g)).into_response(),
        Err(_) => boom("state poisoned"),
    }
}

/// Describe the active verification CA (default vs override, subject, SHA-256)
/// as JSON — shared by the `/dyn/ca_info` route and the Tauri `ca_info` command.
pub fn ca_info_json(g: &AppState) -> serde_json::Value {
    let certs = crate::cert::SignerCert::chain_from_pem_str(g.active_ca());
    // Describe the trust anchor (self-signed root, else the first cert).
    match certs.iter().find(|c| c.is_self_signed()).or_else(|| certs.first()) {
        Some(c) => {
            let fp = c
                .cert_digest(crate::digest::HashAlgo::Sha256)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            json!({ "ok": true, "default": g.ca_is_default(), "count": certs.len(), "subject": c.subject_string(), "sha256": fp })
        }
        None => json!({ "ok": false, "default": g.ca_is_default(), "error": "no certificate in CA chain" }),
    }
}

async fn ok_true() -> Response {
    Json(json!({ "ok": true })).into_response()
}

async fn create_env(State(st): State<Shared>) -> Response {
    let mut g = st.lock().unwrap();
    match g.envs.create_env() {
        Ok((env_id, pub_key_pem)) => Json(CreateEnvResponse { env_id, pub_key_pem }).into_response(),
        Err(e) => boom(e),
    }
}

async fn connect(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let _req = parse(&q, "connect");
    let mut g = st.lock().unwrap();
    match g.ensure_card() {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => boom(e),
    }
}

/// Token + signing-certificate info, no PIN. The "is the card readable?" probe
/// the desktop GUI runs first; keeps all card access in the engine so the GUI
/// never has to touch the driver directly.
async fn get_token_info(State(st): State<Shared>) -> Response {
    let mut g = st.lock().unwrap();
    let result = g.ensure_card().and_then(|card| card.info().map_err(|e| e.to_string()));
    match result {
        Ok(info) => Json(json!({ "ok": true, "info": info })).into_response(),
        Err(e) => {
            g.reset_card(); // self-recover: a wedged read re-opens next time
            boom(e)
        }
    }
}

async fn login(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let req = parse(&q, "login");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    let login_req = match LoginRequest::from_dyn(&req) {
        Ok(l) => l,
        Err(e) => return bad(e),
    };
    let mut g = st.lock().unwrap();
    // Rate-limit: refuse if this env is in a failed-login cooldown. Stops a
    // hostile local page from hammering PIN guesses (which would also burn the
    // card's own retry counter and could lock the cardholder out).
    if let Some(secs) = g.login_lockout_remaining() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("too many failed login attempts; retry in {secs}s"),
        )
            .into_response();
    }
    // Decrypt the PIN with the env private key; never persist it.
    let pin = match g.envs.decrypt_pin(&env, &login_req.encrypted_pin_b64) {
        Some(p) => Zeroizing::new(p),
        None => return bad("PIN decrypt failed / unknown env"),
    };
    let Some(card) = g.card.as_mut() else { return bad("not connected") };
    let r = card.login(pin.as_str());
    match r {
        Ok(()) => {
            g.clear_login_failures();
            Json(LoginResponse { success: true, tries_left: None }).into_response()
        }
        Err(_) => {
            g.record_login_failure();
            // Wrong PIN or a wedged SM channel — drop the session so the next
            // attempt re-establishes Chip-Auth cleanly.
            g.reset_card();
            Json(LoginResponse { success: false, tries_left: None }).into_response()
        }
    }
}

async fn get_certs(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let req = parse(&q, "get_certstore_certificates");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    let g = st.lock().unwrap();
    if !g.envs.contains(&env) {
        return bad("unknown env");
    }
    let Some(card) = g.card.as_ref() else { return bad("not connected/logged in") };
    Json(card.certificates()).into_response()
}

async fn add_file(State(st): State<Shared>, RawQuery(q): RawQuery, body: Bytes) -> Response {
    let req = parse(&q, "cryptoshell_add_file");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    // Bound the upload so any local caller can't OOM the agent with one request.
    if body.len() > MAX_UPLOAD_BYTES {
        return bad(format!(
            "file too large: {} B > {MAX_UPLOAD_BYTES} B limit",
            body.len()
        ));
    }
    // Sanitize the caller-supplied name: strip path components (it must never be
    // usable as a path) and cap its length.
    let raw = req.param("name").unwrap_or("document.pdf");
    let name = std::path::Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("document.pdf")
        .to_string();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return bad("invalid file name");
    }
    let mut g = st.lock().unwrap();
    if !g.envs.contains(&env) {
        return bad("unknown env");
    }
    if g.files.files(&env).len() >= MAX_FILES_PER_ENV {
        return bad(format!("too many files staged for env (max {MAX_FILES_PER_ENV})"));
    }
    g.files.add_file(&env, &name, body.to_vec());
    Json(json!({ "ok": true, "name": name })).into_response()
}

async fn build(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let req = parse(&q, "cryptoshell_build");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    let breq = match CryptoshellBuildRequest::from_dyn(&req) {
        Ok(b) => b,
        Err(e) => return bad(e),
    };
    if breq.op_type != OperationType::Sign {
        return bad("only type=SIGN is implemented");
    }
    // Only our single on-card signing key/cert is valid (handle "1").
    if breq.sign_cert != crate::agent::token::FIRMA_HANDLE
        || breq.sign_key != crate::agent::token::FIRMA_HANDLE
    {
        return bad("unknown sign_cert/sign_key handle");
    }
    // Optional interactive stamp placement (GUI's draggable box):
    // vrect=llx,lly,urx,ury (PDF points) &vfont=<pt> &vpage=<1-based>.
    let placement = req.param("vrect").and_then(|s| {
        let v: Vec<f32> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        (v.len() == 4).then(|| crate::agent::sign::StampPlacement {
            rect: (v[0], v[1], v[2], v[3]),
            font_size: req.param("vfont").and_then(|x| x.parse().ok()).unwrap_or(8.0),
            page: req.param("vpage").and_then(|x| x.parse().ok()).unwrap_or(1),
        })
    });
    // PAdES-T: embed an RFC 3161 timestamp when a TSA is configured — via the
    // `tsa` query param (a calling site may supply one) or the FIRMA_CR_TSA_URL
    // environment variable. Absent both, sign PAdES-B-B as before.
    let tsa_url: Option<String> = req
        .param("tsa")
        .map(|s| s.to_string())
        .or_else(|| std::env::var("FIRMA_CR_TSA_URL").ok())
        .filter(|s| !s.is_empty());
    let mut g = st.lock().unwrap();
    if !g.envs.contains(&env) {
        return bad("unknown env");
    }
    // Sign exactly the files the caller named (intersect with what's staged),
    // not "whatever happens to be staged for this env".
    let files: Vec<_> = g
        .files
        .files(&env)
        .iter()
        .filter(|f| breq.files.contains(&f.name))
        .cloned()
        .collect();
    if files.is_empty() {
        return bad("none of the requested files are staged for env");
    }
    let signed = {
        let Some(card) = g.card.as_ref() else { return bad("not connected/logged in") };
        build_sign(card, &files, Some("Firma Digital"), placement, tsa_url.as_deref())
    };
    let signed = match signed {
        Ok(s) => s,
        Err(e) => {
            g.reset_card(); // wedged sign — re-establish on the next request
            return boom(e);
        }
    };
    let names: Vec<String> = signed.iter().map(|s| s.name.clone()).collect();
    g.signed.insert(env, signed);
    Json(json!({ "ok": true, "files": names })).into_response()
}

async fn download(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let req = parse(&q, "download");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    let want = req.param("file").unwrap_or("").to_string();
    let g = st.lock().unwrap();
    if !g.envs.contains(&env) {
        return bad("unknown env");
    }
    let Some(list) = g.signed.get(&env) else { return bad("no signed files for env") };
    // Require an exact name match — no "first file" fallback (that let a caller
    // who knew only the env id pull the signed document without the filename).
    match list.iter().find(|s| s.name == want) {
        Some(sf) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            sf.bytes.clone(),
        )
            .into_response(),
        None => bad("file not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot

    async fn call(app: &Router, method: &str, uri: &str, body: Option<Vec<u8>>) -> (StatusCode, Vec<u8>) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "127.0.0.1:41231") // pass the anti-rebinding guard
            .body(body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, bytes.to_vec())
    }

    /// Percent-encode a base64 string for a query value (`+ / =` → `%XX`).
    fn urlencode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn make_test_pdf() -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! { "Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Courier" });
        let resources_id = doc.add_object(dictionary! { "Font" => dictionary! { "F1" => font_id } });
        let content = Content { operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 24.into()]),
            Operation::new("Td", vec![100.into(), 600.into()]),
            Operation::new("Tj", vec![Object::string_literal("firma-cr-agent e2e")]),
            Operation::new("ET", vec![]),
        ]};
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! { "Type"=>"Page","Parent"=>pages_id,"Contents"=>content_id,"Resources"=>resources_id });
        doc.objects.insert(pages_id, Object::Dictionary(dictionary! {
            "Type"=>"Pages","Kids"=>vec![page_id.into()],"Count"=>1,"MediaBox"=>vec![0.into(),0.into(),612.into(),792.into()],
        }));
        let catalog_id = doc.add_object(dictionary! { "Type"=>"Catalog","Pages"=>pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn host_is_local_classifies_loopback_only() {
        for h in ["127.0.0.1", "127.0.0.1:41231", "localhost", "LocalHost:41231", "[::1]", "[::1]:41231", "127.5.6.7"] {
            assert!(host_is_local(h), "{h} should be local");
        }
        for h in ["evil.com", "evil.com:41231", "attacker.example:41231", "10.0.0.1", "8.8.8.8:41231", ""] {
            assert!(!host_is_local(h), "{h} should be rejected");
        }
    }

    /// A rebound (non-loopback) Host header is refused before reaching any handler.
    #[tokio::test]
    async fn rebinding_host_is_rejected() {
        let app = app(PathBuf::from("/nonexistent.so"));
        let req = Request::builder()
            .method("GET")
            .uri("/dyn/create_env")
            .header(header::HOST, "attacker.example")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Pure: create_env wiring works with no card.
    #[tokio::test]
    async fn create_env_over_http_returns_envid_and_pubkey() {
        let app = app(PathBuf::from("/nonexistent.so"));
        let (status, body) = call(&app, "GET", "/dyn/create_env", None).await;
        assert_eq!(status, StatusCode::OK);
        let resp: CreateEnvResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.env_id.is_empty());
        assert!(resp.pub_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    /// Pure: login on an unknown env is rejected cleanly (no card touched).
    #[tokio::test]
    async fn login_unknown_env_is_bad_request() {
        let app = app(PathBuf::from("/nonexistent.so"));
        let (status, _) = call(&app, "GET", "/dyn/login?env=nope&token=0&pin=0&e=AAAA", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Integration: the whole `/dyn` sign flow over HTTP against the card-sim.
    /// One per cargo invocation (crfirma PKCS#11 is a process-global singleton):
    ///   cargo test -p firma-cr-agent e2e_dyn_sign_flow -- --ignored
    #[tokio::test]
    #[ignore = "needs card-sim + crfirma (run individually with --ignored)"]
    async fn e2e_dyn_sign_flow_against_sim() {
        use crate::agent::api::Certificate;
        use crate::agent::token::default_module_path;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::{Oaep, RsaPublicKey};
        use rsa::sha2::Sha256;

        let app = app(default_module_path());

        // 1. create_env → envId + pubKeyPem
        let (_, body) = call(&app, "GET", "/dyn/create_env", None).await;
        let env: CreateEnvResponse = serde_json::from_slice(&body).unwrap();

        // 2. connect (open the card)
        let (s, _) = call(&app, "GET", &format!("/dyn/connect?env={}", env.env_id), None).await;
        assert_eq!(s, StatusCode::OK, "connect");

        // 3. login — PIN RSA-encrypted with the env pubkey (like the browser)
        let pk = RsaPublicKey::from_public_key_pem(&env.pub_key_pem).unwrap();
        let mut rng = rand::rngs::OsRng;
        let ct = pk.encrypt(&mut rng, Oaep::new::<Sha256>(), b"1234").unwrap();
        let e = urlencode(&STANDARD.encode(ct));
        let (s, lb) = call(&app, "GET", &format!("/dyn/login?env={}&token=0&pin=0&e={e}", env.env_id), None).await;
        assert_eq!(s, StatusCode::OK, "login");
        let login: LoginResponse = serde_json::from_slice(&lb).unwrap();
        assert!(login.success, "login.success");

        // 4. get_certstore_certificates → one firma cert + handle
        let (_, cb) = call(&app, "GET", &format!("/dyn/get_certstore_certificates?env={}", env.env_id), None).await;
        let certs: Vec<Certificate> = serde_json::from_slice(&cb).unwrap();
        assert_eq!(certs.len(), 1);
        let h = &certs[0].handle;

        // 5. cryptoshell_add_file (POST the PDF)
        let (s, _) = call(&app, "POST", &format!("/dyn/cryptoshell_add_file?env={}&name=doc.pdf", env.env_id), Some(make_test_pdf())).await;
        assert_eq!(s, StatusCode::OK, "add_file");

        // 6. cryptoshell_build type=SIGN
        let files = urlencode(r#"["doc.pdf"]"#);
        let (s, bb) = call(&app, "GET", &format!("/dyn/cryptoshell_build?env={}&type=SIGN&sign_cert={h}&sign_key={h}&files={files}", env.env_id), None).await;
        assert_eq!(s, StatusCode::OK, "build: {}", String::from_utf8_lossy(&bb));

        // 7. download the signed PDF → verify it cryptographically
        let (s, signed) = call(&app, "GET", &format!("/dyn/download?env={}&file=doc-firmado.pdf", env.env_id), None).await;
        assert_eq!(s, StatusCode::OK, "download");
        assert!(signed.windows(10).any(|w| w == b"/ByteRange"), "PAdES /ByteRange present");

        // Re-read the signer cert from the live session to verify against.
        let report = crate::verify::pades::verify_pdf(
            &signed,
            &crate::cert::SignerCert::from_der(
                STANDARD.decode(&certs[0].cert_b64).unwrap(),
            )
            .unwrap(),
            crate::verify::VerifyOptions::default(),
        )
        .expect("verify_pdf");
        assert!(report.ok, "signature did not verify:\n{}", report.pretty());
    }
}
