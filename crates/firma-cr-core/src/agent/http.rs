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

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, StatusCode};
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
}

impl AppState {
    pub fn new(module_path: PathBuf) -> Self {
        Self {
            envs: EnvStore::new(),
            card: None,
            files: FileStore::new(),
            signed: HashMap::new(),
            module_path,
        }
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
        .layer(cors)
        .with_state(state)
}

/// Build the `/dyn` router with fresh state. `module_path` is the crfirma `.so`.
pub fn app(module_path: PathBuf) -> Router {
    app_with_state(Arc::new(Mutex::new(AppState::new(module_path))))
}

/// Bind and serve on `127.0.0.1:41231` over an existing shared state.
pub async fn serve_with_state(state: Shared) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 41231)).await?;
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
    match g.ensure_card() {
        Ok(card) => match card.info() {
            Ok(info) => Json(json!({ "ok": true, "info": info })).into_response(),
            Err(e) => boom(e.to_string()),
        },
        Err(e) => boom(e),
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
    // Decrypt the PIN with the env private key; never persist it.
    let pin = match g.envs.decrypt_pin(&env, &login_req.encrypted_pin_b64) {
        Some(p) => Zeroizing::new(p),
        None => return bad("PIN decrypt failed / unknown env"),
    };
    let Some(card) = g.card.as_mut() else { return bad("not connected") };
    match card.login(pin.as_str()) {
        Ok(()) => Json(LoginResponse { success: true, tries_left: None }).into_response(),
        Err(_) => Json(LoginResponse { success: false, tries_left: None }).into_response(),
    }
}

async fn get_certs(State(st): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let _req = parse(&q, "get_certstore_certificates");
    let g = st.lock().unwrap();
    let Some(card) = g.card.as_ref() else { return bad("not connected/logged in") };
    Json(card.certificates()).into_response()
}

async fn add_file(State(st): State<Shared>, RawQuery(q): RawQuery, body: Bytes) -> Response {
    let req = parse(&q, "cryptoshell_add_file");
    let Some(env) = req.env.clone() else { return bad("missing env") };
    let name = req.param("name").unwrap_or("document.pdf").to_string();
    let mut g = st.lock().unwrap();
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
    let mut g = st.lock().unwrap();
    let files = g.files.files(&env).to_vec();
    if files.is_empty() {
        return bad("no files staged for env");
    }
    let signed = {
        let Some(card) = g.card.as_ref() else { return bad("not connected/logged in") };
        build_sign(card, &files, Some("Firma Digital"))
    };
    let signed = match signed {
        Ok(s) => s,
        Err(e) => return boom(e),
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
    let Some(list) = g.signed.get(&env) else { return bad("no signed files for env") };
    match list.iter().find(|s| s.name == want).or_else(|| list.first()) {
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
