//! The stored credential: pi's `OAuthCredential` JSON.
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{Error, TokenStore};

/// The `expires` of a credential that never expires: JavaScript's
/// `Number.MAX_SAFE_INTEGER`, which pi writes for OpenRouter's key.
pub const NEVER: i64 = 9_007_199_254_740_991;

/// pi's `OAuthCredential`, the JSON kept per provider:
/// `{"type":"oauth","access","refresh","expires"}`, plus the client id
/// ChatGPT issued and the scopes it granted. `expires` is milliseconds since
/// the epoch. `Debug` never shows the tokens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    #[serde(rename = "type")]
    kind: Kind,
    pub access: String,
    pub refresh: String,
    pub expires: i64,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Kind {
    #[serde(rename = "oauth")]
    OAuth,
}

impl Credential {
    pub(crate) fn new(access: String, refresh: String, expires: i64) -> Self {
        Self {
            kind: Kind::OAuth,
            access,
            refresh,
            expires,
            client_id: None,
            scopes: None,
        }
    }

    /// Whether less than `window` of validity remains at `now` (milliseconds
    /// since the epoch).
    pub fn expires_within(&self, window: Duration, now: i64) -> bool {
        now.saturating_add(millis(window)) >= self.expires
    }

    pub(crate) async fn load(store: &dyn TokenStore, key: &str) -> Result<Option<Self>, Error> {
        let Some(record) = store.load(key).await.map_err(Error::Store)? else {
            return Ok(None);
        };
        // serde's message can quote a value, and a value can be a token.
        serde_json::from_str(&record).map(Some).map_err(|e| {
            Error::Invalid(format!(
                "the stored {key} credential is not an OAuth credential (line {}, column {})",
                e.line(),
                e.column()
            ))
        })
    }

    pub(crate) async fn save(&self, store: &dyn TokenStore, key: &str) -> Result<(), Error> {
        let record = serde_json::to_string(self).map_err(|e| Error::Invalid(e.to_string()))?;
        store.save(key, &record).await.map_err(Error::Store)
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("expires", &self.expires)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// Milliseconds since the epoch, as JavaScript's `Date.now()`.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, millis)
}

pub(crate) fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}
