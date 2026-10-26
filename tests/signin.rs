//! Both sign-ins against a fake auth server: OpenAI's token endpoint and
//! OpenRouter's key endpoints, which check PKCE as the real ones do and
//! rotate refresh tokens. A test plays the browser and the user who
//! approves: it reads the authorize URL and calls the callback itself.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::extract::{Form, State};
use axum::http::header::LOCATION;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use model_signin::{
    ChatGpt, Credential, Error, FileTokenStore, KeyStatus, MemoryTokenStore, OpenRouter,
    TokenStore, device_id, now,
};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

const DEVICE: &str = "6F9619FF-8B86-D011-B42D-00C04FC964FF";
const ISSUED: &str = "agent-client-7";
const RESOURCE: &str = "https://api.openai.com/v1";
const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const KEY: &str = "sk-or-v1-fake";
const APP_CALLBACK: &str = "https://app.example/api/openrouter/callback";

#[derive(Default)]
struct Auth {
    /// Authorization code → the challenge, client and redirect it was issued for.
    grants: HashMap<String, Grant>,
    /// Refresh token → still unspent.
    unspent: HashMap<String, bool>,
    issued: usize,
    refreshes: usize,
    scope: String,
    id_token: bool,
    /// How long a refresh takes to answer, after its token is spent.
    delay: Duration,
    keys: Keys,
    /// Where the token and key endpoints send every POST, with a 307.
    redirect: Option<String>,
    /// The POSTs they answered so.
    redirected: usize,
}

struct Grant {
    challenge: String,
    client_id: String,
    redirect: String,
}

#[derive(Default, Clone, Copy)]
enum Keys {
    #[default]
    Key,
    Refuse,
    NoKey,
    NotJson,
}

impl Auth {
    fn tokens(&mut self, id_token: bool) -> Value {
        self.issued += 1;
        let refresh = format!("refresh-{}", self.issued);
        self.unspent.insert(refresh.clone(), true);
        let mut body = json!({
            "access_token": format!("access-{}", self.issued),
            "refresh_token": refresh,
            "expires_in": 3600,
            "scope": self.scope,
            "token_type": "Bearer",
        });
        if id_token && self.id_token {
            body["id_token"] = json!("header.payload.signature");
        }
        body
    }

    /// The 307 a POST gets when the endpoints redirect, with the page a
    /// server sends along.
    fn redirect(&mut self) -> Option<Response> {
        let location = self.redirect.clone()?;
        self.redirected += 1;
        let page = format!("<a href=\"{location}\">Temporary Redirect</a>");
        Some((StatusCode::TEMPORARY_REDIRECT, [(LOCATION, location)], page).into_response())
    }
}

type Shared = Arc<Mutex<Auth>>;

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn token(State(auth): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    if let Some(redirect) = auth.lock().unwrap().redirect() {
        return redirect;
    }
    let field = |name: &str| form.get(name).map_or("", String::as_str);
    let refused = |why: &str| {
        // It echoes the request, verifier or refresh token included, which no error may quote.
        let body = json!({"error": "invalid_grant", "error_description": why, "request": form});
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    };
    if field("resource") != RESOURCE {
        return refused("wrong resource");
    }
    let delay = {
        let mut auth = auth.lock().unwrap();
        match field("grant_type") {
            "authorization_code" => {
                let Some(grant) = auth.grants.remove(field("code")) else {
                    return refused("unknown code");
                };
                if grant.client_id != field("client_id") || grant.redirect != field("redirect_uri")
                {
                    return refused("wrong client or redirect_uri");
                }
                if challenge(field("code_verifier")) != grant.challenge {
                    return refused("PKCE verification failed");
                }
                return Json(auth.tokens(true)).into_response();
            }
            "refresh_token" => {
                if field("client_id") != ISSUED {
                    return refused("wrong client");
                }
                match auth.unspent.get_mut(field("refresh_token")) {
                    Some(unspent) if *unspent => *unspent = false,
                    _ => return refused("refresh token reused or unknown"),
                }
                auth.refreshes += 1;
                auth.delay
            }
            _ => return refused("unsupported grant_type"),
        }
    };
    tokio::time::sleep(delay).await;
    let body = auth.lock().unwrap().tokens(false);
    Json(body).into_response()
}

async fn keys(State(auth): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut auth = auth.lock().unwrap();
    if let Some(redirect) = auth.redirect() {
        return redirect;
    }
    match auth.keys {
        Keys::Refuse => {
            let body = json!({"error": {"message": "Invalid code", "code": 403}});
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }
        Keys::NoKey => Json(json!({"user_id": "user-1"})).into_response(),
        Keys::NotJson => "<html>maintenance</html>".into_response(),
        Keys::Key => {
            let text = |name: &str| body[name].as_str().unwrap_or("").to_owned();
            let grant = auth.grants.remove(&text("code"));
            let method = text("code_challenge_method");
            if grant.is_some_and(|g| g.challenge == challenge(&text("code_verifier")))
                && method == "S256"
            {
                Json(json!({"key": KEY, "user_id": "user-1"})).into_response()
            } else {
                let body = json!({"error": {"message": "PKCE verification failed"}});
                (StatusCode::BAD_REQUEST, Json(body)).into_response()
            }
        }
    }
}

async fn key(headers: HeaderMap) -> Response {
    let bearer = headers.get("authorization").and_then(|v| v.to_str().ok());
    if bearer == Some(&format!("Bearer {KEY}")) {
        Json(json!({"data": {"label": "sk-or-v1-fak...", "limit": null, "usage": 0.25}}))
            .into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

struct Fake {
    url: String,
    auth: Shared,
}

impl Fake {
    async fn start() -> Self {
        let auth = Shared::new(Mutex::new(Auth {
            scope: SCOPE.into(),
            id_token: true,
            ..Auth::default()
        }));
        let app = Router::new()
            .route("/api/accounts/oauth/token", post(token))
            .route("/api/v1/auth/keys", post(keys))
            .route("/api/v1/key", get(key))
            .with_state(Arc::clone(&auth));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, auth }
    }

    fn auth(&self) -> MutexGuard<'_, Auth> {
        self.auth.lock().unwrap()
    }

    /// The user approves the sign-in at `authorize`: a code is issued for its
    /// challenge, and the redirect it names is returned with the code, the
    /// state and, when given, the issued client id.
    fn approve(&self, authorize: &str, client_id: Option<&str>) -> Url {
        static CODES: AtomicUsize = AtomicUsize::new(0);
        let url = Url::parse(authorize).unwrap();
        let param = |name: &str| {
            url.query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        let redirect = param("redirect_uri")
            .or_else(|| param("callback_url"))
            .unwrap();
        let code = format!("code-{}", CODES.fetch_add(1, Ordering::SeqCst));
        self.auth().grants.insert(
            code.clone(),
            Grant {
                challenge: param("code_challenge").unwrap(),
                client_id: client_id.unwrap_or(ISSUED).into(),
                redirect: redirect.clone(),
            },
        );
        let mut callback = Url::parse(&redirect).unwrap();
        let mut query = callback.query_pairs_mut();
        query.append_pair("code", &code);
        if let Some(state) = param("state") {
            query.append_pair("state", &state);
        }
        if let Some(client_id) = client_id {
            query.append_pair("client_id", client_id);
        }
        drop(query);
        callback
    }
}

/// A server on another port, which reqwest counts as another host: a
/// redirect there would lose its headers but keep its body. It records
/// every request that reaches it.
struct Elsewhere {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Elsewhere {
    async fn start() -> Self {
        let seen = Arc::default();
        let app = Router::new().fallback(record).with_state(Arc::clone(&seen));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, seen }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

async fn record(
    State(seen): State<Arc<Mutex<Vec<String>>>>,
    method: Method,
    uri: Uri,
    body: String,
) {
    seen.lock().unwrap().push(format!("{method} {uri} {body}"));
}

fn scratch() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("signin-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn param(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

fn with_param(url: &Url, name: &str, value: &str) -> Url {
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let mut changed = url.clone();
    changed.query_pairs_mut().clear().extend_pairs(
        pairs
            .iter()
            .map(|(k, v)| (k.as_str(), if k == name { value } else { v.as_str() })),
    );
    changed
}

fn chatgpt(fake: &Fake, store: impl TokenStore + 'static) -> ChatGpt {
    ChatGpt::new(store, "example-app")
        .issuer(&fake.url)
        .callback_port(0)
        .timeout(Duration::from_secs(5))
}

/// Runs a ChatGPT sign-in to its end, approved at `authorize` (the sign-in's
/// own URL unless a test changes it) with `client_id` in the callback.
async fn finish_chatgpt(
    fake: &Fake,
    gpt: &ChatGpt,
    tamper: impl FnOnce(Url) -> Url,
    client_id: Option<&str>,
) -> (u16, String, Result<Credential, Error>) {
    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let callback = fake.approve(
        tamper(Url::parse(sign_in.url()).unwrap()).as_str(),
        client_id,
    );
    let finishing = tokio::spawn(sign_in.finish());
    let page = reqwest::get(callback).await.unwrap();
    let status = page.status().as_u16();
    (status, page.text().await.unwrap(), finishing.await.unwrap())
}

/// A credential that expires within the refresh window, holding `refresh`,
/// which the fake treats as unspent.
async fn seed_expiring(
    fake: &Fake,
    store: &dyn TokenStore,
    refresh: &str,
    client_id: Option<&str>,
) {
    fake.auth().unspent.insert(refresh.into(), true);
    let mut record = json!({
        "type": "oauth", "access": "access-old", "refresh": refresh, "expires": now() + 60_000,
        "scopes": ["openid", "chatgpt.tokens.use.direct"],
    });
    if let Some(client_id) = client_id {
        record["clientId"] = json!(client_id);
    }
    store.save("openai", &record.to_string()).await.unwrap();
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never: {what}");
}

#[tokio::test]
async fn chatgpt_sign_in_verifies_pkce_and_stores_pis_credential() {
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let url = Url::parse(sign_in.url()).unwrap();
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(url.path(), "/api/accounts/authorize");
    assert_eq!(params["client_id"], "dynamic_agent_client");
    assert_eq!(params["agent_name_hint"], "example-app");
    assert_eq!(
        params["ext_agent_host_id"],
        format!("urn:uuid:{}", DEVICE.to_lowercase())
    );
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["resource"], RESOURCE);
    assert_eq!(params["scope"], SCOPE);
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(params["redirect_uri"].starts_with("http://127.0.0.1:"));
    assert!(params["redirect_uri"].ends_with("/auth/callback"));
    assert_eq!((params["state"].len(), params["nonce"].len()), (43, 43));
    assert_ne!(params["state"], params["nonce"]);

    let callback = fake.approve(url.as_str(), Some(ISSUED));
    let finishing = tokio::spawn(sign_in.finish());
    let page = reqwest::get(callback).await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.text().await.unwrap().contains("ChatGPT is connected"));
    let credential = finishing.await.unwrap().unwrap();

    let file = dir.join("openai.json");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.starts_with(r#"{"type":"oauth","access":"access-1","refresh":"refresh-1","expires":"#)
    );
    let stored: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(stored["clientId"], ISSUED);
    assert_eq!(
        stored["scopes"],
        json!(SCOPE.split(' ').collect::<Vec<_>>())
    );
    let expected = now() + 3_600_000 - 180_000;
    assert!((expected - stored["expires"].as_i64().unwrap()).abs() < 5_000);
    #[cfg(unix)]
    assert_eq!(mode(&file), 0o600);
    let debug = format!("{credential:?}");
    assert!(
        !debug.contains("access-1") && !debug.contains("refresh-1"),
        "{debug}"
    );
    assert_eq!(
        gpt.access_token().await.unwrap().as_deref(),
        Some("access-1")
    );
}

#[tokio::test]
async fn chatgpt_code_without_the_matching_verifier_is_refused() {
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    // The authorization server saw a challenge this sign-in's verifier does not answer.
    let other = |url: Url| with_param(&url, "code_challenge", &challenge("another verifier"));
    let (status, page, result) = finish_chatgpt(&fake, &gpt, other, Some(ISSUED)).await;
    assert_eq!(status, 502);
    assert!(page.contains("PKCE verification failed"), "{page}");
    let error = result.unwrap_err();
    assert!(matches!(error, Error::Refused(_)));
    assert_eq!(
        error.to_string(),
        "OpenAI OAuth token request failed (400): invalid_grant (PKCE verification failed)"
    );
    assert!(!dir.join("openai.json").exists());
}

#[tokio::test]
async fn chatgpt_callback_with_another_state_is_refused_and_the_sign_in_waits() {
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let callback = fake.approve(sign_in.url(), Some(ISSUED));
    let finishing = tokio::spawn(sign_in.finish());
    let forged = with_param(&callback, "state", "forged");
    let page = reqwest::get(forged).await.unwrap();
    assert_eq!(page.status(), 400);
    assert!(page.text().await.unwrap().contains("OAuth state mismatch"));
    assert!(!finishing.is_finished());
    assert!(!dir.join("openai.json").exists());

    let page = reqwest::get(callback).await.unwrap();
    assert_eq!(page.status(), 200);
    finishing.await.unwrap().unwrap();
    assert!(dir.join("openai.json").exists());
}

#[tokio::test]
async fn chatgpt_callback_without_an_issued_client_id_fails() {
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    let (status, page, result) = finish_chatgpt(&fake, &gpt, |url| url, None).await;
    let message = "OpenAI OAuth registration callback did not contain an issued client ID";
    assert_eq!(status, 400);
    assert!(page.contains(message), "{page}");
    assert_eq!(result.unwrap_err().to_string(), message);
    assert!(!dir.join("openai.json").exists());
}

#[tokio::test]
async fn chatgpt_grant_without_the_direct_scope_or_an_id_token_fails() {
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    fake.auth().scope = "openid profile email offline_access resource.invoke".into();
    let (status, _, result) = finish_chatgpt(&fake, &gpt, |url| url, Some(ISSUED)).await;
    assert_eq!(status, 502);
    let expected = "OpenAI OAuth grant did not include chatgpt.tokens.use.direct";
    assert_eq!(result.unwrap_err().to_string(), expected);

    {
        let mut auth = fake.auth();
        (auth.scope, auth.id_token) = (SCOPE.into(), false);
    }
    let (_, _, result) = finish_chatgpt(&fake, &gpt, |url| url, Some(ISSUED)).await;
    let expected = "OpenAI OAuth token response did not contain an ID token";
    assert_eq!(result.unwrap_err().to_string(), expected);
    assert!(!dir.join("openai.json").exists());
}

#[tokio::test]
async fn chatgpt_sign_in_fails_clearly_when_the_port_is_taken() {
    let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port();
    let gpt = ChatGpt::new(MemoryTokenStore::default(), "example-app").callback_port(port);
    let Err(error) = gpt.sign_in(DEVICE).await else {
        panic!("signed in on a port another listener holds");
    };
    assert!(matches!(error, Error::PortInUse(p) if p == port));
    let message = error.to_string();
    assert!(
        message.starts_with(&format!("port {port} is in use")),
        "{message}"
    );
    assert!(gpt.sign_in("not-a-uuid").await.is_err());
}

#[tokio::test]
async fn a_finished_sign_in_closes_every_connection() {
    let fake = Fake::start().await;
    let gpt = chatgpt(&fake, MemoryTokenStore::default());
    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let port = Url::parse(&param(&Url::parse(sign_in.url()).unwrap(), "redirect_uri"))
        .unwrap()
        .port()
        .unwrap();
    // A browser's spare connection, opened ahead of time and never used.
    let mut spare = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let callback = fake.approve(sign_in.url(), Some(ISSUED));
    let finishing = tokio::spawn(sign_in.finish());
    assert_eq!(reqwest::get(callback).await.unwrap().status(), 200);
    finishing.await.unwrap().unwrap();
    let read = tokio::time::timeout(Duration::from_secs(1), spare.read(&mut [0; 1])).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the spare connection stayed open"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn return_to_sends_the_browser_back_to_the_app_after_the_outcome() {
    const APP: &str = "http://127.0.0.1:3000/";
    let no_redirects = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let fake = Fake::start().await;
    let dir = scratch();
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir)).return_to(APP);

    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let callback = fake.approve(sign_in.url(), Some(ISSUED));
    let finishing = tokio::spawn(sign_in.finish());
    let answer = no_redirects.get(callback).send().await.unwrap();
    assert_eq!(answer.status(), 303);
    assert_eq!(answer.headers()["location"], APP);
    // The redirect leaves only once the credential is stored.
    assert!(dir.join("openai.json").exists());
    finishing.await.unwrap().unwrap();

    // A refusal also goes back, and the app reads why from `finish`.
    let sign_in = gpt.sign_in(DEVICE).await.unwrap();
    let url = Url::parse(sign_in.url()).unwrap();
    let mut denied = Url::parse(&param(&url, "redirect_uri")).unwrap();
    denied
        .query_pairs_mut()
        .append_pair("state", &param(&url, "state"))
        .append_pair("error", "access_denied");
    let finishing = tokio::spawn(sign_in.finish());
    let answer = no_redirects.get(denied).send().await.unwrap();
    assert_eq!(answer.status(), 303);
    assert_eq!(answer.headers()["location"], APP);
    assert_eq!(
        finishing.await.unwrap().unwrap_err().to_string(),
        "ChatGPT authorization failed: access_denied"
    );

    let error = ChatGpt::new(MemoryTokenStore::default(), "example-app")
        .return_to("javascript:alert(1)")
        .sign_in(DEVICE)
        .await
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .starts_with("return_to must be an http or https URL")
    );
}

#[tokio::test]
async fn two_processes_refreshing_at_once_refresh_once() {
    let fake = Fake::start().await;
    let dir = scratch();
    seed_expiring(&fake, &FileTokenStore::new(&dir), "refresh-0", Some(ISSUED)).await;
    fake.auth().delay = Duration::from_millis(100);
    // Two stores over one directory stand for two processes: they share only the file lock.
    let first = chatgpt(&fake, FileTokenStore::new(&dir));
    let second = chatgpt(&fake, FileTokenStore::new(&dir));
    let (a, b) = tokio::join!(first.access_token(), second.access_token());
    assert_eq!(fake.auth().refreshes, 1);
    let (a, b) = (a.unwrap().unwrap(), b.unwrap().unwrap());
    assert_eq!((a.as_str(), b.as_str()), ("access-1", "access-1"));
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("openai.json")).unwrap()).unwrap();
    assert_eq!(
        (stored["access"].as_str(), stored["refresh"].as_str()),
        (Some("access-1"), Some("refresh-1"))
    );
    assert_eq!(stored["clientId"], ISSUED);
}

/// rig's file store and this crate's over one directory: the same files and
/// the same lock, so this crate and rig's authenticators can share a
/// directory.
#[cfg(feature = "rig")]
#[tokio::test]
async fn this_crates_file_store_and_rigs_share_files_and_lock() {
    use model_signin::rig::RigStore;
    use rig_core::providers::chatgpt::auth as rig_auth;

    let fake = Fake::start().await;
    let dir = scratch();
    seed_expiring(&fake, &FileTokenStore::new(&dir), "refresh-0", Some(ISSUED)).await;
    fake.auth().delay = Duration::from_millis(100);
    let ours = chatgpt(&fake, FileTokenStore::new(&dir));
    let rigs = chatgpt(&fake, RigStore(rig_auth::FileTokenStore::new(&dir)));
    let (a, b) = tokio::join!(ours.access_token(), rigs.access_token());
    assert_eq!(fake.auth().refreshes, 1);
    assert_eq!(a.unwrap().as_deref(), Some("access-1"));
    assert_eq!(b.unwrap().as_deref(), Some("access-1"));

    // This crate's store is a rig store too, holding rig's lock against rig's.
    let rig_view: &dyn rig_auth::TokenStore = &FileTokenStore::new(&dir);
    let record = rig_view.load("openai").await.unwrap().unwrap();
    assert!(record.contains(r#""refresh":"refresh-1""#));
    let held = rig_view.lock("openai").await.unwrap();
    let other: &dyn rig_auth::TokenStore = &rig_auth::FileTokenStore::new(&dir);
    let waiting = tokio::time::timeout(Duration::from_millis(200), other.lock("openai")).await;
    assert!(
        waiting.is_err(),
        "rig's store took a lock this crate's holds"
    );
    drop(held);
    other.lock("openai").await.unwrap();
}

#[cfg(feature = "rig")]
#[test]
fn the_chatgpt_dialect_is_openai_on_the_codex_contract() {
    use rig_core::providers::openai::wire::{OPENAI, ResponsesContract};

    let dialect = model_signin::rig::chatgpt_dialect();
    assert_eq!(dialect.base_url, OPENAI.base_url);
    assert_eq!(dialect.quirks.responses.contract, ResponsesContract::Codex);
}

#[tokio::test]
async fn clones_over_a_store_without_a_lock_refresh_once() {
    let fake = Fake::start().await;
    let store = Arc::new(MemoryTokenStore::default());
    seed_expiring(&fake, store.as_ref(), "refresh-0", Some(ISSUED)).await;
    fake.auth().delay = Duration::from_millis(50);
    let gpt = chatgpt(&fake, Arc::clone(&store));
    let other = gpt.clone();
    let (a, b) = tokio::join!(gpt.access_token(), other.access_token());
    assert_eq!(fake.auth().refreshes, 1);
    assert_eq!(a.unwrap(), b.unwrap());
}

#[tokio::test]
async fn a_started_refresh_outlives_its_caller() {
    let fake = Fake::start().await;
    let dir = scratch();
    seed_expiring(&fake, &FileTokenStore::new(&dir), "refresh-0", Some(ISSUED)).await;
    fake.auth().delay = Duration::from_millis(150);
    let gpt = chatgpt(&fake, FileTokenStore::new(&dir));
    // The caller gives up while the refresh is in flight and refresh-0 is already spent.
    let gave_up = tokio::time::timeout(Duration::from_millis(60), gpt.access_token()).await;
    assert!(gave_up.is_err());
    assert_eq!(fake.auth().refreshes, 1);
    let file = dir.join("openai.json");
    eventually("the rotated token is saved", || {
        std::fs::read_to_string(&file)
            .unwrap()
            .contains(r#""refresh":"refresh-1""#)
    })
    .await;
    assert_eq!(
        gpt.access_token().await.unwrap().as_deref(),
        Some("access-1")
    );
    assert_eq!(fake.auth().refreshes, 1);
}

#[tokio::test]
async fn a_token_with_time_left_is_used_and_a_refresh_needs_the_issued_client() {
    let fake = Fake::start().await;
    let store = Arc::new(MemoryTokenStore::default());
    let gpt = chatgpt(&fake, Arc::clone(&store));
    assert_eq!(gpt.access_token().await.unwrap(), None);
    let fresh = json!({"type": "oauth", "access": "access-kept", "refresh": "r", "expires": now() + 3_600_000});
    store.save("openai", &fresh.to_string()).await.unwrap();
    assert_eq!(
        gpt.access_token().await.unwrap().as_deref(),
        Some("access-kept")
    );
    seed_expiring(&fake, store.as_ref(), "refresh-0", None).await;
    let error = gpt.access_token().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not contain an issued client ID; reconnect ChatGPT")
    );
    assert_eq!(fake.auth().refreshes, 0);
    gpt.sign_out().await.unwrap();
    assert_eq!(gpt.access_token().await.unwrap(), None);
}

#[tokio::test]
async fn openrouter_sign_in_run_by_the_apps_server_stores_a_permanent_key() {
    let fake = Fake::start().await;
    let dir = scratch();
    let openrouter = OpenRouter::new(FileTokenStore::new(&dir)).base(&fake.url);
    let url = Url::parse(&openrouter.start(APP_CALLBACK)).unwrap();
    assert_eq!(url.path(), "/auth");
    assert_eq!(param(&url, "code_challenge_method"), "S256");
    let callback_url = param(&url, "callback_url");
    let flow = callback_url
        .strip_prefix(&format!("{APP_CALLBACK}/"))
        .unwrap();
    assert_eq!(flow.len(), 36);

    // OpenRouter redirects to the app's server, which routes the flow and code here.
    let callback = fake.approve(url.as_str(), None);
    assert_eq!(callback.path(), format!("/api/openrouter/callback/{flow}"));
    let code = param(&callback, "code");
    let credential = openrouter.finish(flow, &code).await.unwrap();
    assert_eq!(credential.access, KEY);
    let file = dir.join("openrouter.json");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!(r#"{{"type":"oauth","access":"{KEY}","refresh":"","expires":9007199254740991}}"#)
    );
    #[cfg(unix)]
    assert_eq!(mode(&file), 0o600);
    let status = openrouter.key_status().await.unwrap();
    assert_eq!(
        status,
        Some(KeyStatus {
            limit: None,
            usage: 0.25
        })
    );
    assert!(matches!(
        openrouter.finish(flow, &code).await,
        Err(Error::Expired)
    ));
}

#[tokio::test]
async fn openrouter_exchange_errors_store_nothing() {
    let fake = Fake::start().await;
    let dir = scratch();
    let openrouter = OpenRouter::new(FileTokenStore::new(&dir)).base(&fake.url);
    let attempt = |answer: Keys, tamper: bool| {
        fake.auth().keys = answer;
        let mut url = Url::parse(&openrouter.start(APP_CALLBACK)).unwrap();
        if tamper {
            url = with_param(&url, "code_challenge", &challenge("another verifier"));
        }
        let callback = fake.approve(url.as_str(), None);
        let flow = callback.path().rsplit('/').next().unwrap().to_owned();
        let openrouter = openrouter.clone();
        async move {
            openrouter
                .finish(&flow, &param(&callback, "code"))
                .await
                .unwrap_err()
                .to_string()
        }
    };
    assert_eq!(
        attempt(Keys::Refuse, false).await,
        "OpenRouter OAuth key exchange failed (HTTP 403): Invalid code"
    );
    assert_eq!(
        attempt(Keys::Key, true).await,
        "OpenRouter OAuth key exchange failed (HTTP 400): PKCE verification failed"
    );
    assert_eq!(
        attempt(Keys::NoKey, false).await,
        r#"OpenRouter OAuth response carries no "key""#
    );
    assert_eq!(
        attempt(Keys::NotJson, false).await,
        "OpenRouter OAuth returned invalid JSON"
    );

    assert!(matches!(
        openrouter.finish("no-such-flow", "code").await,
        Err(Error::Expired)
    ));
    let brief = openrouter.clone().flow_ttl(Duration::from_millis(1));
    let url = Url::parse(&brief.start(APP_CALLBACK)).unwrap();
    let flow = param(&url, "callback_url")
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(matches!(
        brief.finish(&flow, "code").await,
        Err(Error::Expired)
    ));
    assert!(openrouter.credential().await.unwrap().is_none());
    assert!(!dir.join("openrouter.json").exists());
}

#[tokio::test]
async fn openrouter_sign_in_behind_a_loopback_listener() {
    let fake = Fake::start().await;
    let store = Arc::new(MemoryTokenStore::default());
    let openrouter = OpenRouter::new(Arc::clone(&store)).base(&fake.url);
    let sign_in = openrouter.sign_in().await.unwrap();
    let callback = fake.approve(sign_in.url(), None);
    assert!(callback.as_str().starts_with("http://127.0.0.1:"));
    assert!(callback.path().starts_with("/oauth/callback/"));
    let finishing = tokio::spawn(sign_in.finish());
    let stray = callback.join("/favicon.ico").unwrap();
    assert_eq!(reqwest::get(stray).await.unwrap().status(), 404);
    let page = reqwest::get(callback).await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("OpenRouter is connected")
    );
    assert_eq!(finishing.await.unwrap().unwrap().access, KEY);
    assert!(
        store
            .load("openrouter")
            .await
            .unwrap()
            .unwrap()
            .contains(KEY)
    );
}

#[tokio::test]
async fn a_redirect_from_the_token_or_key_endpoint_fails_and_is_not_followed() {
    let fake = Fake::start().await;
    let elsewhere = Elsewhere::start().await;
    fake.auth().redirect = Some(format!("{}/token", elsewhere.url));
    let store = Arc::new(MemoryTokenStore::default());
    let gpt = chatgpt(&fake, Arc::clone(&store));
    let openrouter = OpenRouter::new(Arc::clone(&store)).base(&fake.url);
    // Three POSTs with secrets in their bodies: ChatGPT's code and verifier,
    // its refresh token, and OpenRouter's code and verifier.
    let (status, _, signed_in) = finish_chatgpt(&fake, &gpt, |url| url, Some(ISSUED)).await;
    seed_expiring(&fake, store.as_ref(), "refresh-0", Some(ISSUED)).await;
    let refreshed = gpt.access_token().await;
    let callback = fake.approve(&openrouter.start(APP_CALLBACK), None);
    let flow = callback.path().rsplit('/').next().unwrap();
    let exchanged = openrouter.finish(flow, &param(&callback, "code")).await;

    assert_eq!(elsewhere.seen(), Vec::<String>::new());
    assert_eq!(fake.auth().redirected, 3);
    let refused = "OpenAI OAuth token request failed (307): Temporary Redirect";
    assert_eq!(status, 502);
    assert_eq!(signed_in.unwrap_err().to_string(), refused);
    let error = refreshed.unwrap_err();
    assert!(matches!(error, Error::Refused(_)));
    assert_eq!(error.to_string(), refused);
    assert_eq!(
        exchanged.unwrap_err().to_string(),
        "OpenRouter OAuth key exchange failed (HTTP 307)"
    );
}

#[test]
fn device_id_is_made_once_and_kept_private() {
    let dir = scratch().join("auth");
    let id = device_id(&dir).unwrap();
    assert_eq!(
        id.split('-').map(str::len).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12]
    );
    assert_eq!(device_id(&dir).unwrap(), id);
    #[cfg(unix)]
    assert_eq!((mode(&dir), mode(&dir.join("device-id"))), (0o700, 0o600));
}
