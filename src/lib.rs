//! Sign in with ChatGPT and OpenRouter's OAuth PKCE, for an app that keeps
//! its credentials in any [`TokenStore`]. The `rig` feature adds a connector
//! to rig-core ([`rig`]).
//!
//! Both flows are ported from pi-ai (github.com/earendil-works/pi, MIT,
//! © Mario Zechner) at commit `d5b3de22d0e24a3e9c38a9410d3329b099717283`:
//! `packages/ai/src/auth/oauth/openrouter.ts`, `openai-chatgpt.ts`, and the
//! refresh in `auth/resolve.ts`.
//!
//! - [`openrouter`]: PKCE, with the code exchanged for a permanent key. An app
//!   with its own HTTP server runs it from its routes ([`OpenRouter::start`]
//!   and [`OpenRouter::finish`]); a program without one runs it behind a
//!   loopback listener ([`OpenRouter::sign_in`]).
//! - [`chatgpt`]: Sign in with ChatGPT for the OpenAI Responses API. The flow
//!   registers a dynamic client, listens on 127.0.0.1:1455 only while it
//!   waits, and refreshes the token under the store's lock.
//!
//! Each credential is pi's `OAuthCredential` JSON, kept under pi's provider
//! id (`openrouter`, `openai`), so pi and this crate write the same shape.
//! [`FileTokenStore`] keeps one 0600 file per provider and holds a file lock
//! on it across processes. Nothing here prints or logs a token:
//! [`Credential`]'s `Debug` leaves them out.

pub mod chatgpt;
mod credential;
mod loopback;
pub mod openrouter;
mod pkce;
#[cfg(feature = "rig")]
pub mod rig;
pub mod store;

pub use chatgpt::{ChatGpt, device_id};
pub use credential::{Credential, NEVER, now};
pub use openrouter::{KeyStatus, OpenRouter};
pub use store::{FileTokenStore, MemoryTokenStore, StoreLock, TokenStore};

/// Why a sign-in, refresh or key check failed. A message quotes the
/// provider's own words where it gave some, and never a token.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Another listener holds the callback port.
    #[error(
        "port {0} is in use, probably by an unfinished sign-in in another process or by the Codex CLI; cancel that sign-in and try again"
    )]
    PortInUse(u16),
    /// The provider refused the authorization, the code, the refresh or the key.
    #[error("{0}")]
    Refused(String),
    /// The provider's answer, or a stored credential, broke the flow's contract.
    #[error("{0}")]
    Invalid(String),
    /// No callback came before the deadline, or a request ran too long.
    #[error("{0} timed out")]
    TimedOut(&'static str),
    /// An OpenRouter sign-in that is unknown, expired or already finished.
    #[error("this sign-in has expired or already finished; start a new one")]
    Expired,
    /// The request could not be sent or its answer read.
    #[error("{0}")]
    Http(#[from] reqwest::Error),
    /// The token store could not load, save, delete or lock.
    #[error("token store: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// The client for the providers' endpoints, which follows no redirect.
/// reqwest's default re-sends a 307 or 308's body to the new location and
/// strips only the headers when that is another host, so a code, its
/// verifier or a refresh token would go too. The flows refuse a 3xx instead.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("an HTTP client")
}
