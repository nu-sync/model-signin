//! The connector to rig-core, behind the `rig` feature.
//!
//! - [`RigStore`] runs the flows over any of rig's `TokenStore`s.
//! - [`FileTokenStore`] and [`MemoryTokenStore`] are rig `TokenStore`s too,
//!   so one store serves this crate and rig's own authenticators.
//! - [`chatgpt_dialect`] and [`chatgpt_config`] send what api.openai.com
//!   accepts with a Sign in with ChatGPT token.
use rig_core::providers::chatgpt::auth as rig_auth;
use rig_core::providers::openai::OpenAIConfig;
use rig_core::providers::openai::wire::{Dialect, OPENAI, ResponsesContract};

use crate::store::{BoxError, BoxFuture};
use crate::{FileTokenStore, MemoryTokenStore, StoreLock, TokenStore};

/// One of rig's `TokenStore`s, as this crate's: `ChatGpt::new(RigStore(store), …)`.
#[derive(Debug, Clone, Default)]
pub struct RigStore<S>(pub S);

impl<S: rig_auth::TokenStore> TokenStore for RigStore<S> {
    fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        self.0.load(key)
    }

    fn save<'a>(&'a self, key: &'a str, record: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        self.0.save(key, record)
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
        self.0.delete(key)
    }

    fn lock<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<StoreLock, BoxError>> {
        Box::pin(async move { self.0.lock(key).await.map(StoreLock::new) })
    }
}

macro_rules! rig_token_store {
    ($store:ty) => {
        impl rig_auth::TokenStore for $store {
            fn load<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
                TokenStore::load(self, key)
            }

            fn save<'a>(
                &'a self,
                key: &'a str,
                record: &'a str,
            ) -> BoxFuture<'a, Result<(), BoxError>> {
                TokenStore::save(self, key, record)
            }

            fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BoxError>> {
                TokenStore::delete(self, key)
            }

            fn lock<'a>(
                &'a self,
                key: &'a str,
            ) -> BoxFuture<'a, Result<rig_auth::StoreLock, BoxError>> {
                Box::pin(async move {
                    TokenStore::lock(self, key)
                        .await
                        .map(rig_auth::StoreLock::new)
                })
            }
        }
    };
}

rig_token_store!(FileTokenStore);
rig_token_store!(MemoryTokenStore);

/// rig's OpenAI dialect, still at `https://api.openai.com/v1`, on its Codex
/// contract. With a ChatGPT token, api.openai.com wants `store: false`,
/// takes only a streamed request with a list input, and names no content
/// type on the stream; pi also sends no `max_output_tokens`, `temperature`
/// or prompt-cache fields. The Codex contract is all of that.
pub fn chatgpt_dialect() -> Dialect {
    let mut dialect = OPENAI;
    dialect.quirks.responses.contract = ResponsesContract::Codex;
    dialect
}

/// An OpenAI config for a token from [`ChatGpt::access_token`](crate::ChatGpt::access_token),
/// on [`chatgpt_dialect`]. The token expires: build a config per request,
/// or at least once it has less than five minutes left.
pub fn chatgpt_config(token: impl Into<String>) -> OpenAIConfig {
    OpenAIConfig::with_key(&chatgpt_dialect(), token.into())
}
