# Upstreaming model-signin to rig

What contributing this crate to rig
([0xPlaygrounds/rig](https://github.com/0xPlaygrounds/rig), MIT) would take,
as of rig-core 0.45.0. Three additions, and the work to make them rig's
own.

## 1. `openrouter::auth`

rig's `openrouter` provider takes an API key only. Upstream, the key could
come from an authenticator like `chatgpt::auth`'s, with
`AuthSource::{ApiKey, OAuth}`, whose sign-in is `openrouter.rs`:

- PKCE, the key exchange, and the flow id in the callback path.
- Both shapes: an app's own server calling `start` and `finish`, and a
  loopback listener for a CLI.

The record is a permanent key with no refresh, so it uses rig's store and
`Shell::hold` and none of the refresh machinery. `key_status` maps onto
rig's `verify()`.

## 2. A Sign in with ChatGPT authenticator for `openai`

rig's `chatgpt` provider is a different flow. It signs in as the Codex CLI
(client `app_EMoamEEZ73f0CkXaXp7hrann`, scope
`openid profile email offline_access`, ports 1455 or 1457) and sends
requests to `chatgpt.com/backend-api/codex` with a `ChatGPT-Account-Id`.

The flow here is the newer one:

- Every sign-in registers a client through `dynamic_agent_client`, and the
  callback carries the issued id.
- It asks for `resource=https://api.openai.com/v1` and the scopes
  `resource.invoke chatgpt.tokens.use.direct`, and names the app with
  `agent_name_hint` and `ext_agent_host_id`.
- The token is a bearer for `api.openai.com/v1`, with no account header.

Upstream it would be an `openai::auth::Authenticator`, or an
`AuthSource::ChatGpt` on `OpenAIConfig`, built on rig's `Shell`.
`Shell::hold` already takes the in-process lock and then the store's, and
`Remembered` already caches a live token. Three things change:

- **A refresh outlives its caller.** rig refreshes inside the caller's
  future (`auth_context_oauth` awaits `refresh_tokens` while it holds the
  locks). A caller dropped mid-refresh loses the rotated refresh token
  unless another client saved one. pi's rule, followed here, spawns the
  refresh and its save, bounded by a timeout.
- **The window is five minutes.** rig refreshes 60 seconds before expiry;
  pi refreshes with five minutes left, on top of a stored expiry already 3
  minutes early.
- **The record and the options grow.** The record keeps `clientId` and
  `scopes`, and a sign-in takes the app's device id and name, as pi's
  `LoginOptions` does.

## 3. A flag that sends what a ChatGPT token accepts

With a Sign in with ChatGPT token, api.openai.com holds a request to rules
an API key is not held to:

- It refuses `stream: false` ("Stream must be set to true") and a string
  `input` ("Input must be a list").
- It answers with an event stream that has no `Content-Type`.
- pi leaves out `max_output_tokens`, `temperature`,
  `prompt_cache_retention`, `prompt_cache_options` and
  `configuration_update` items for the token, and always sends
  `store: false` (`isChatGPTSignIn` in pi's `api/openai-responses.ts`).

rig already has this behaviour as `ResponsesContract::Codex`: always
streamed, an unlabelled reply accepted, `store: false` forced (the
`CodexStore` rewrite), and no sampling, output-cap or structured-output
fields. Only the `chatgpt` dialect uses it today. `model_signin::rig::chatgpt_dialect` gets the
behaviour by copying the `OPENAI` dialect and setting
`quirks.responses.contract = ResponsesContract::Codex`, and the call works
against api.openai.com.

Upstream, the flag should be public and named. One option is an
`OpenAIConfig` setting, or an `AuthSource` from the new authenticator,
that selects the contract for the OpenAI dialect. The other is a
`ResponsesContract::ChatGptSignIn` that shares the Codex rewrites but keeps
structured output, if the endpoint takes it with the token. That was not
tried here, and pi sends none. Both choices need a test against the live
endpoint.

## The work to make it rig's

- **Transport and errors.** Send through rig's `HttpClientExt` (rig-http)
  instead of reqwest, return rig's `AuthError` instead of this crate's
  `Error`, and gate the listeners to native targets, as
  `chatgpt::auth::native` is.
- **No redirects on auth requests.** This crate builds its client with
  `redirect::Policy::none()`. rig's default transport follows redirects,
  and a 307 or 308 re-sends the form body (a code, its verifier or a refresh
  token) to the new host. rig's own ChatGPT exchange and refresh have the
  same exposure today, so the fix belongs in rig's auth path for every
  sign-in.
- **What stays out.** This crate's `TokenStore`, `FileTokenStore` and
  `MemoryTokenStore` follow rig's, and the flows use rig's directly. The
  `rig` connector and its store adapters go away. An app's credential
  directory and agent name stay in the app.
- **Tests.** The fake-server tests here move to rig's test style.
- **Credit.** pi's logic is followed closely (MIT, © 2025 Mario Zechner),
  so the contribution credits pi as this crate does.
