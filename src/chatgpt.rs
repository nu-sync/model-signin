//! Sign in with ChatGPT for the OpenAI Responses API
//! (<https://developers.openai.com/cookbook/articles/sign-in-with-chatgpt>),
//! following pi's `openai-chatgpt.ts`. Every sign-in registers a new client
//! through `dynamic_agent_client`; OpenAI returns the issued client id with
//! the callback, and the token goes straight to `https://api.openai.com/v1`.
//! rig's own `chatgpt` provider is a different flow: it signs in as the Codex
//! CLI (`app_EMoamEEZ73f0CkXaXp7hrann`) and calls `chatgpt.com/backend-api/codex`.
//!
//! The refresh follows pi's `auth/resolve.ts`: a token with less than
//! [`MIN_VALIDITY`] left is refreshed under the in-process lock and the
//! store's, checked again once they are held, and saved before they are let
//! go. A refresh that
//! has started runs to its end even if its caller gives up, because OpenAI
//! rotates refresh tokens: the old one is spent once the request is sent.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use reqwest::header::ACCEPT;
use serde_json::{Map, Value};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::credential::millis;
use crate::loopback::{Loopback, Request};
use crate::pkce::{challenge, random_value, uuid};
use crate::{Credential, Error, StoreLock, TokenStore, now};

/// The key the credential is kept under: pi's provider id for OpenAI.
pub const STORE_KEY: &str = "openai";
/// The API the token is for, sent as the OAuth `resource`.
pub const RESOURCE: &str = "https://api.openai.com/v1";
/// A token with less than this left is refreshed before it is used.
pub const MIN_VALIDITY: Duration = Duration::from_secs(5 * 60);
/// The port OpenAI redirects to.
pub const CALLBACK_PORT: u16 = 1455;

const ISSUER: &str = "https://auth.openai.com";
const DYNAMIC_CLIENT_ID: &str = "dynamic_agent_client";
const CALLBACK_PATH: &str = "/auth/callback";
const DIRECT_TOKEN_SCOPE: &str = "chatgpt.tokens.use.direct";
const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
/// The stored expiry is this much before the real one, so a request never
/// starts with a token about to expire.
const EXPIRY_MARGIN: Duration = Duration::from_secs(3 * 60);
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
/// A refresh that has started is bounded by this, never by its caller.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(15);

/// Sign in with ChatGPT over one token store. Clones share the store and
/// the in-process refresh lock.
#[derive(Clone)]
pub struct ChatGpt {
    store: Arc<dyn TokenStore>,
    http: reqwest::Client,
    issuer: String,
    agent_name: String,
    callback_port: u16,
    timeout: Duration,
    return_to: Option<String>,
    // For stores whose own lock holds nothing in this process, such as MemoryTokenStore.
    local: Arc<Mutex<()>>,
}

impl ChatGpt {
    /// Sign-ins that introduce the app to OpenAI as `agent_name`.
    pub fn new(store: impl TokenStore + 'static, agent_name: impl Into<String>) -> Self {
        Self {
            store: Arc::new(store),
            http: crate::http_client(),
            issuer: ISSUER.into(),
            agent_name: agent_name.into(),
            callback_port: CALLBACK_PORT,
            timeout: SIGN_IN_TIMEOUT,
            return_to: None,
            local: Arc::default(),
        }
    }

    /// Another origin for the authorize and token endpoints, such as a test's server.
    #[must_use]
    pub fn issuer(mut self, url: impl Into<String>) -> Self {
        self.issuer = url.into();
        self
    }

    /// Another callback port, 0 for a free one: only a test server honours it.
    #[must_use]
    pub fn callback_port(mut self, port: u16) -> Self {
        self.callback_port = port;
        self
    }

    /// How long a sign-in waits for its callback (ten minutes).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Where the browser goes once the sign-in ends, such as the app's own
    /// page, instead of the listener's "ChatGPT is connected" page. The
    /// callback answers with a 303 to `url` after the code is exchanged and
    /// the credential stored, or after the sign-in failed; the app shows
    /// which from what [`SignIn::finish`] returned. An `http` or `https` URL.
    #[must_use]
    pub fn return_to(mut self, url: impl Into<String>) -> Self {
        self.return_to = Some(url.into());
        self
    }

    /// Starts a sign-in for this installation (`device_id`, a UUID; see
    /// [`device_id`]): listens on 127.0.0.1:1455 and returns the page to open.
    /// Fails at once if another listener holds the port.
    pub async fn sign_in(&self, device_id: &str) -> Result<SignIn, Error> {
        let host = agent_host_id(device_id)?;
        let return_to = match &self.return_to {
            None => None,
            Some(url) => match Url::parse(url) {
                Ok(url) if matches!(url.scheme(), "http" | "https") => Some(url),
                _ => {
                    return Err(Error::Invalid(format!(
                        "return_to must be an http or https URL: {url}"
                    )));
                }
            },
        };
        let listener = Loopback::bind(self.callback_port).await?;
        let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", listener.port());
        let (verifier, state) = (random_value(), random_value());
        let mut url = Url::parse(&format!("{}/api/accounts/authorize", self.issuer))
            .map_err(|e| Error::Invalid(format!("issuer: {e}")))?;
        url.query_pairs_mut()
            .append_pair("client_id", DYNAMIC_CLIENT_ID)
            .append_pair("agent_name_hint", &self.agent_name)
            .append_pair("ext_agent_host_id", &host)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("resource", RESOURCE)
            .append_pair("scope", SCOPE)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge(&verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", &random_value());
        Ok(SignIn {
            url: url.into(),
            listener,
            verifier,
            state,
            redirect_uri,
            return_to,
            owner: self.clone(),
        })
    }

    /// The stored credential, refreshed first when less than
    /// [`MIN_VALIDITY`] of it is left; `None` when nobody signed in.
    pub async fn credential(&self) -> Result<Option<Credential>, Error> {
        match Credential::load(self.store.as_ref(), STORE_KEY).await? {
            Some(credential) if !expiring(&credential) => return Ok(Some(credential)),
            None => return Ok(None),
            Some(_) => {}
        }
        // Only the waits for the locks may be cancelled: nothing is sent yet.
        let held = self.hold().await?;
        let owner = self.clone();
        let refresh = tokio::spawn(async move {
            let _held = held;
            let current = match Credential::load(owner.store.as_ref(), STORE_KEY).await? {
                Some(credential) if expiring(&credential) => credential,
                // Signed out meanwhile, or refreshed by another holder of the lock.
                other => return Ok(other),
            };
            let next = tokio::time::timeout(REFRESH_TIMEOUT, owner.refresh(&current))
                .await
                .map_err(|_| Error::TimedOut("the ChatGPT token refresh"))??;
            next.save(owner.store.as_ref(), STORE_KEY).await?;
            Ok(Some(next))
        });
        refresh
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?
    }

    /// The access token to send as `Authorization: Bearer`, fresh as
    /// [`ChatGpt::credential`] keeps it.
    pub async fn access_token(&self) -> Result<Option<String>, Error> {
        Ok(self.credential().await?.map(|credential| credential.access))
    }

    /// Forgets the stored credential.
    pub async fn sign_out(&self) -> Result<(), Error> {
        let _held = self.hold().await?;
        self.store.delete(STORE_KEY).await.map_err(Error::Store)
    }

    /// The in-process lock, then the store's, in rig's authenticators' order.
    async fn hold(&self) -> Result<(StoreLock, OwnedMutexGuard<()>), Error> {
        let local = Arc::clone(&self.local).lock_owned().await;
        let store = self.store.lock(STORE_KEY).await.map_err(Error::Store)?;
        Ok((store, local))
    }

    async fn refresh(&self, credential: &Credential) -> Result<Credential, Error> {
        let Some(client_id) = credential
            .client_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
        else {
            return Err(Error::Invalid(
                "Stored OpenAI OAuth credential does not contain an issued client ID; reconnect ChatGPT".into(),
            ));
        };
        let token = self
            .token(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", &credential.refresh),
                ("resource", RESOURCE),
            ])
            .await?;
        issued(&token, client_id)
    }

    async fn token(&self, form: &[(&str, &str)]) -> Result<Map<String, Value>, Error> {
        let response = self
            .http
            .post(format!("{}/api/accounts/oauth/token", self.issuer))
            .header(ACCEPT, "application/json")
            .form(form)
            .timeout(TOKEN_TIMEOUT)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            // OAuth's two error fields and nothing else: a body can carry anything.
            let body = response.json::<Value>().await.unwrap_or_default();
            let field = |name: &str| {
                body.get(name)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            };
            let detail = match (field("error"), field("error_description")) {
                (Some(error), Some(description)) => format!("{error} ({description})"),
                (error, description) => error
                    .or(description)
                    .or(status.canonical_reason())
                    .unwrap_or("")
                    .into(),
            };
            return Err(Error::Refused(format!(
                "OpenAI OAuth token request failed ({}): {}",
                status.as_u16(),
                detail.chars().take(500).collect::<String>()
            )));
        }
        match response.json::<Value>().await? {
            Value::Object(token) => Ok(token),
            _ => Err(Error::Invalid(
                "OpenAI OAuth token response must be an object".into(),
            )),
        }
    }
}

/// A sign-in waiting for its callback on 127.0.0.1:1455.
pub struct SignIn {
    url: String,
    listener: Loopback,
    verifier: String,
    state: String,
    redirect_uri: String,
    return_to: Option<Url>,
    owner: ChatGpt,
}

impl SignIn {
    /// The page to open in the browser.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Waits for the callback, exchanges its code, stores the credential and
    /// closes the listener with every connection. A request that is not this
    /// sign-in's (another path, or a missing or different `state`) is
    /// refused and the wait goes on; a callback with this sign-in's state
    /// ends it either way.
    pub async fn finish(mut self) -> Result<Credential, Error> {
        let deadline = tokio::time::Instant::now() + self.owner.timeout;
        loop {
            let request = match tokio::time::timeout_at(deadline, self.listener.next()).await {
                Ok(Some(request)) => request,
                Ok(None) => return Err(Error::Io(std::io::Error::other("the listener stopped"))),
                Err(_) => return Err(Error::TimedOut("Sign in with ChatGPT")),
            };
            if let Some(result) = self.answer(request).await {
                return result;
            }
        }
    }

    async fn answer(&self, request: Request) -> Option<Result<Credential, Error>> {
        const NOT_CONNECTED: &str = "ChatGPT was not connected";
        if request.url().path() != CALLBACK_PATH {
            request
                .reply(404, "Not found", "This page is not part of the sign-in.")
                .await;
            return None;
        }
        if request.param("state").as_deref() != Some(&self.state) {
            request
                .reply(400, NOT_CONNECTED, "OAuth state mismatch.")
                .await;
            return None;
        }
        let authorized = match (request.param("error"), request.param("code")) {
            (Some(error), _) => Err(Error::Refused(format!(
                "ChatGPT authorization failed: {error}"
            ))),
            (None, Some(code)) if !code.is_empty() => {
                match request.param("client_id").map(|id| id.trim().to_owned()) {
                    Some(client_id) if !client_id.is_empty() => Ok((code, client_id)),
                    _ => Err(Error::Invalid(
                        "OpenAI OAuth registration callback did not contain an issued client ID"
                            .into(),
                    )),
                }
            }
            (None, _) => Err(Error::Invalid("Missing authorization code".into())),
        };
        // A bad callback is the browser's error (400); a failed exchange, OpenAI's (502).
        let (result, failed_status) = match authorized {
            Ok((code, client_id)) => (self.exchange(&code, &client_id).await, 502),
            Err(error) => (Err(error), 400),
        };
        // Answered only now, so whichever page the browser lands on can tell
        // the truth about the credential.
        match (&self.return_to, &result) {
            (Some(url), _) => request.redirect(url).await,
            (None, Ok(_)) => {
                request
                    .reply(200, "ChatGPT is connected", "You can close this window.")
                    .await
            }
            (None, Err(e)) => {
                request
                    .reply(failed_status, NOT_CONNECTED, &e.to_string())
                    .await
            }
        }
        Some(result)
    }

    async fn exchange(&self, code: &str, client_id: &str) -> Result<Credential, Error> {
        let token = self
            .owner
            .token(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", code),
                ("code_verifier", &self.verifier),
                ("redirect_uri", &self.redirect_uri),
                ("resource", RESOURCE),
            ])
            .await?;
        // Nothing reads the ID token; its presence is part of the response's contract, as in pi.
        if token
            .get("id_token")
            .and_then(Value::as_str)
            .is_none_or(|id| id.trim().is_empty())
        {
            return Err(Error::Invalid(
                "OpenAI OAuth token response did not contain an ID token".into(),
            ));
        }
        let credential = issued(&token, client_id)?;
        let _held = self.owner.hold().await?;
        credential
            .save(self.owner.store.as_ref(), STORE_KEY)
            .await?;
        Ok(credential)
    }
}

/// The credential a token response grants, which must include the direct-use scope.
fn issued(token: &Map<String, Value>, client_id: &str) -> Result<Credential, Error> {
    let text = |field: &str| {
        token
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                Error::Invalid(format!("OpenAI OAuth token response has invalid {field}"))
            })
    };
    let (access, refresh, scope) = (
        text("access_token")?,
        text("refresh_token")?,
        text("scope")?,
    );
    let Some(expires_in) = token
        .get("expires_in")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
    else {
        return Err(Error::Invalid(
            "OpenAI OAuth token response has invalid expires_in".into(),
        ));
    };
    let scopes: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
    if !scopes.iter().any(|granted| granted == DIRECT_TOKEN_SCOPE) {
        return Err(Error::Invalid(format!(
            "OpenAI OAuth grant did not include {DIRECT_TOKEN_SCOPE}"
        )));
    }
    let expires = now() + (expires_in * 1000.0) as i64 - millis(EXPIRY_MARGIN);
    let mut credential = Credential::new(access.into(), refresh.into(), expires);
    credential.client_id = Some(client_id.into());
    credential.scopes = Some(scopes);
    Ok(credential)
}

fn expiring(credential: &Credential) -> bool {
    credential.expires_within(MIN_VALIDITY, now())
}

/// OpenAI names an installation ("agent host") by a URI: `urn:uuid:<uuid>`.
fn agent_host_id(device_id: &str) -> Result<String, Error> {
    let id = device_id.to_ascii_lowercase();
    let shape = id.split('-').map(str::len).eq([8, 4, 4, 4, 12]);
    if !shape || !id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()) {
        return Err(Error::Invalid(
            "Sign in with ChatGPT requires a device ID (UUID) for this installation".into(),
        ));
    }
    Ok(format!("urn:uuid:{id}"))
}

/// This installation's stable id, kept in `<dir>/device-id` (0600, its
/// directory 0700) and made on first use.
pub fn device_id(dir: &Path) -> std::io::Result<String> {
    use std::io::Write;

    let path = dir.join("device-id");
    match std::fs::read_to_string(&path) {
        Ok(id) if !id.trim().is_empty() => return Ok(id.trim().to_owned()),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    }
    builder.create(dir)?;
    match options.open(&path) {
        Ok(mut file) => file.write_all(uuid().as_bytes())?,
        // Another process made it first.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    Ok(std::fs::read_to_string(&path)?.trim().to_owned())
}
