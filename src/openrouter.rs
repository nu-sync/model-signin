//! OpenRouter's OAuth PKCE (<https://openrouter.ai/docs/use-cases/oauth-pkce>),
//! following pi's `openrouter.ts`: the code is exchanged for a permanent key,
//! stored with no refresh token and an expiry of [`NEVER`].
//!
//! An app with its own HTTP server runs it from two routes:
//! [`OpenRouter::start`] gives the page to open, whose callback reaches the
//! app at `<callback>/<flow>?code=…`, and [`OpenRouter::finish`] exchanges
//! that code. OpenRouter sends no `state`; the random flow id in the path is
//! what ties a callback to its sign-in, and each flow finishes once.
//! [`OpenRouter::sign_in`] runs the same two steps behind a loopback listener
//! on a free port, for a program without a server.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use reqwest::Url;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde_json::{Value, json};

use crate::loopback::Loopback;
use crate::pkce::{challenge, random_value, uuid};
use crate::{Credential, Error, NEVER, TokenStore};

/// The key the credential is kept under: pi's provider id.
pub const STORE_KEY: &str = "openrouter";

const BASE: &str = "https://openrouter.ai";
const CALLBACK_PATH: &str = "/oauth/callback";
const FLOW_TTL: Duration = Duration::from_secs(10 * 60);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const KEY_TIMEOUT: Duration = Duration::from_secs(10);

/// OpenRouter sign-ins over one token store. Clones share the store and the
/// pending sign-ins.
#[derive(Clone)]
pub struct OpenRouter {
    store: Arc<dyn TokenStore>,
    http: reqwest::Client,
    base: String,
    flow_ttl: Duration,
    flows: Arc<Mutex<HashMap<String, Pending>>>,
}

struct Pending {
    verifier: String,
    started: Instant,
}

/// The stored key's spend, from `GET /api/v1/key`.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyStatus {
    /// USD; `None` when the key has no limit.
    pub limit: Option<f64>,
    /// USD spent so far.
    pub usage: f64,
}

impl OpenRouter {
    pub fn new(store: impl TokenStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            http: crate::http_client(),
            base: BASE.into(),
            flow_ttl: FLOW_TTL,
            flows: Arc::default(),
        }
    }

    /// Another origin for `/auth` and `/api/v1/…`, such as a test's server.
    #[must_use]
    pub fn base(mut self, url: impl Into<String>) -> Self {
        self.base = url.into();
        self
    }

    /// How long a started sign-in may wait for its callback (ten minutes).
    #[must_use]
    pub fn flow_ttl(mut self, ttl: Duration) -> Self {
        self.flow_ttl = ttl;
        self
    }

    /// Starts a sign-in whose callback is `<callback>/<flow>` and returns
    /// the URL to open.
    pub fn start(&self, callback: &str) -> String {
        self.start_flow(callback).1
    }

    fn start_flow(&self, callback: &str) -> (String, String) {
        let verifier = random_value();
        let mut url = Url::parse(&format!("{}/auth", self.base)).expect("an OpenRouter origin");
        let flow = uuid();
        url.query_pairs_mut()
            .append_pair("callback_url", &format!("{callback}/{flow}"))
            .append_pair("code_challenge", &challenge(&verifier))
            .append_pair("code_challenge_method", "S256");
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.retain(|_, pending| pending.started.elapsed() <= self.flow_ttl);
        let started = Instant::now();
        flows.insert(flow.clone(), Pending { verifier, started });
        (flow, url.into())
    }

    /// Exchanges the callback's `code` for a key and stores it. A flow
    /// finishes once, whatever the outcome.
    pub async fn finish(&self, flow: &str, code: &str) -> Result<Credential, Error> {
        let pending = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(flow)
            .filter(|pending| pending.started.elapsed() <= self.flow_ttl)
            .ok_or(Error::Expired)?;
        let credential = self.exchange(code, &pending.verifier).await?;
        let _lock = self.store.lock(STORE_KEY).await.map_err(Error::Store)?;
        credential.save(self.store.as_ref(), STORE_KEY).await?;
        Ok(credential)
    }

    async fn exchange(&self, code: &str, verifier: &str) -> Result<Credential, Error> {
        let body =
            json!({"code": code, "code_verifier": verifier, "code_challenge_method": "S256"});
        let response = self
            .http
            .post(format!("{}/api/v1/auth/keys", self.base))
            .header(ACCEPT, "application/json")
            .json(&body)
            .timeout(EXCHANGE_TIMEOUT)
            .send()
            .await
            .map_err(timed_out)?;
        let status = response.status();
        let body = response.bytes().await.map_err(timed_out)?;
        let body = serde_json::from_slice::<Value>(&body).ok();
        if !status.is_success() {
            let detail = body.as_ref().and_then(error_detail);
            return Err(Error::Refused(format!(
                "OpenRouter OAuth key exchange failed (HTTP {}){}",
                status.as_u16(),
                detail.map(|d| format!(": {d}")).unwrap_or_default()
            )));
        }
        let Some(body) = body else {
            return Err(Error::Invalid(
                "OpenRouter OAuth returned invalid JSON".into(),
            ));
        };
        match body.get("key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => Ok(Credential::new(key.into(), String::new(), NEVER)),
            _ => Err(Error::Invalid(
                "OpenRouter OAuth response carries no \"key\"".into(),
            )),
        }
    }

    /// The stored credential, if any. Its key never expires.
    pub async fn credential(&self) -> Result<Option<Credential>, Error> {
        Credential::load(self.store.as_ref(), STORE_KEY).await
    }

    /// Forgets the stored key. It stays valid at OpenRouter until revoked there.
    pub async fn sign_out(&self) -> Result<(), Error> {
        let _lock = self.store.lock(STORE_KEY).await.map_err(Error::Store)?;
        self.store.delete(STORE_KEY).await.map_err(Error::Store)
    }

    /// One free authenticated call (`GET /api/v1/key`), which proves the
    /// stored key works; `None` when nothing is stored.
    pub async fn key_status(&self) -> Result<Option<KeyStatus>, Error> {
        let Some(credential) = self.credential().await? else {
            return Ok(None);
        };
        let response = self
            .http
            .get(format!("{}/api/v1/key", self.base))
            .header(AUTHORIZATION, format!("Bearer {}", credential.access))
            .timeout(KEY_TIMEOUT)
            .send()
            .await
            .map_err(timed_out)?;
        if !response.status().is_success() {
            return Err(Error::Refused(format!(
                "OpenRouter refused the stored key (HTTP {})",
                response.status().as_u16()
            )));
        }
        let body: Value = response.json().await?;
        let data = &body["data"];
        Ok(Some(KeyStatus {
            limit: data["limit"].as_f64(),
            usage: data["usage"].as_f64().unwrap_or(0.0),
        }))
    }

    /// Starts a sign-in whose callback reaches a listener on 127.0.0.1 at a
    /// free port, for a program with no server of its own.
    pub async fn sign_in(&self) -> Result<SignIn, Error> {
        let listener = Loopback::bind(0).await?;
        let callback = format!("http://127.0.0.1:{}{CALLBACK_PATH}", listener.port());
        let (flow, url) = self.start_flow(&callback);
        Ok(SignIn {
            url,
            path: format!("{CALLBACK_PATH}/{flow}"),
            flow,
            listener,
            owner: self.clone(),
        })
    }
}

/// A loopback sign-in waiting for its callback.
pub struct SignIn {
    url: String,
    path: String,
    flow: String,
    listener: Loopback,
    owner: OpenRouter,
}

impl SignIn {
    /// The page to open in the browser.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Waits for the callback, exchanges its code and stores the key, then
    /// closes the listener. Gives up after the flow's time to live.
    pub async fn finish(mut self) -> Result<Credential, Error> {
        let deadline = tokio::time::Instant::now() + self.owner.flow_ttl;
        loop {
            let request = match tokio::time::timeout_at(deadline, self.listener.next()).await {
                Ok(Some(request)) => request,
                Ok(None) => return Err(Error::Io(std::io::Error::other("the listener stopped"))),
                Err(_) => return Err(Error::TimedOut("the OpenRouter sign-in")),
            };
            if request.url().path() != self.path {
                request
                    .reply(404, "Not found", "This page is not part of the sign-in.")
                    .await;
                continue;
            }
            if let Some(error) = request.param("error") {
                let detail = request.param("error_description").unwrap_or(error);
                request
                    .reply(400, "OpenRouter was not connected", &detail)
                    .await;
                return Err(Error::Refused(format!(
                    "OpenRouter authorization failed: {detail}"
                )));
            }
            let Some(code) = request.param("code") else {
                request
                    .reply(
                        400,
                        "OpenRouter was not connected",
                        "Missing authorization code.",
                    )
                    .await;
                continue;
            };
            let result = self.owner.finish(&self.flow, &code).await;
            match &result {
                Ok(_) => {
                    request
                        .reply(200, "OpenRouter is connected", "You can close this window.")
                        .await
                }
                Err(e) => {
                    request
                        .reply(502, "OpenRouter was not connected", &e.to_string())
                        .await
                }
            }
            return result;
        }
    }
}

/// pi's `errorDetail`: the provider's own words, wherever it put them.
fn error_detail(body: &Value) -> Option<String> {
    ["error_description", "message", "error"]
        .iter()
        .find_map(|field| body[field].as_str())
        .or_else(|| body["error"]["message"].as_str())
        .map(str::to_owned)
}

fn timed_out(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::TimedOut("the OpenRouter request")
    } else {
        Error::Http(error)
    }
}
