# model-signin

Sign in with ChatGPT and OpenRouter's OAuth PKCE for Rust apps, with the
credentials kept in any `TokenStore`. The flows are ported from
[pi](https://github.com/earendil-works/pi). They hand out a bearer token or
an API key for any HTTP client or model library. An optional connector,
the `rig` feature, joins them to
[rig-core](https://github.com/0xPlaygrounds/rig), and the crate is shaped to
contribute to rig ([docs/UPSTREAM.md](docs/UPSTREAM.md)).

Status: 0.1, and its API may change. The `rig` feature needs rig-core 0.45.

```toml
model-signin = "0.1"
# or, with the rig connector:
model-signin = { version = "0.1", features = ["rig"] }
```

## What it does

| Flow | Follows | What happens |
| --- | --- | --- |
| OpenRouter OAuth PKCE ([docs](https://openrouter.ai/docs/use-cases/oauth-pkce)) | pi `auth/oauth/openrouter.ts` | S256 PKCE. `openrouter.ai/auth?callback_url&code_challenge&code_challenge_method=S256`, with a random flow id in the callback path because OpenRouter sends no `state`. `POST /api/v1/auth/keys {code, code_verifier, code_challenge_method}` returns a permanent key, stored as `{"type":"oauth","access":<key>,"refresh":"","expires":9007199254740991}`. `GET /api/v1/key` proves the key works. An app's own HTTP server runs it from two routes (`start`, then `finish` from its callback route), or a loopback listener on a free port does (`sign_in`). |
| Sign in with ChatGPT ([docs](https://developers.openai.com/siwc)) | pi `auth/oauth/openai-chatgpt.ts` | Authorize at `auth.openai.com/api/accounts/authorize` with `client_id=dynamic_agent_client`, `agent_name_hint`, `ext_agent_host_id=urn:uuid:<device id>`, `resource=https://api.openai.com/v1`, the scope `openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`, S256 PKCE, `state` and `nonce`. A listener on `127.0.0.1:1455` lives only while the sign-in waits, fails at once if the port is taken, and closes every connection when it ends. The callback's `state` is checked, and its `code` and issued `client_id` are read. The exchange at `/api/accounts/oauth/token` must return an ID token and grant `chatgpt.tokens.use.direct`. The credential is stored with `clientId` and `scopes`, and with `expires` 3 minutes before the real expiry. |
| Refresh | pi `auth/resolve.ts` | A ChatGPT token with less than 5 minutes left is refreshed with `grant_type=refresh_token`, the issued client id and the `resource`. The refresh takes the in-process lock and then the store's lock, checks the token again once it holds them, and saves before letting go. Once started, it runs in its own task, bounded by 15 s and never by its caller, because OpenAI rotates refresh tokens. |

With `FileTokenStore`, the credentials are `<dir>/openai.json` and
`<dir>/openrouter.json`, 0600 files in a 0700 directory. Each is written
whole, through a rename, and a file lock on `<dir>/<key>.lock` holds it
across processes. The JSON is pi's `OAuthCredential`. `<dir>/device-id`
(0600) holds the installation's id, which OpenAI records as the agent host.
Any other `TokenStore` works too: `MemoryTokenStore`, or your own over a
keychain or a database. `FileTokenStore` follows rig's, so the two over one
directory share the same files and the same lock. `Credential`'s `Debug` leaves the tokens out, and
nothing here prints one.

## Using it

OpenRouter, from an app's own HTTP server:

```rust
use model_signin::{FileTokenStore, OpenRouter};

let openrouter = OpenRouter::new(FileTokenStore::new("/path/to/credentials"));
// The route that starts a sign-in sends the user to this page.
let page = openrouter.start("https://app.example/api/openrouter/callback");
// The callback route, GET /api/openrouter/callback/{flow}?code=…, finishes it.
let credential = openrouter.finish(&flow, &code).await?;
```

OpenRouter, from a program without a server:

```rust
let sign_in = openrouter.sign_in().await?; // 127.0.0.1, a free port
println!("open {}", sign_in.url());
sign_in.finish().await?;
```

Sign in with ChatGPT:

```rust
use model_signin::{ChatGpt, FileTokenStore, device_id};

let dir = std::path::Path::new("/path/to/credentials");
let chatgpt = ChatGpt::new(FileTokenStore::new(dir), "My App")
    // Optional: once the sign-in ends, send the browser back to the app
    // instead of showing "ChatGPT is connected" on 127.0.0.1:1455.
    .return_to("http://127.0.0.1:3000/");
let sign_in = chatgpt.sign_in(&device_id(dir)?).await?; // fails at once if 1455 is taken
println!("open {}", sign_in.url());
sign_in.finish().await?;
// Before each request: a token with at least five minutes left, refreshed if not.
let token = chatgpt.access_token().await?.ok_or("not signed in")?;
```

## With rig

```toml
model-signin = { version = "0.1", features = ["rig"] }
```

The `rig` feature adds `model_signin::rig`:

- `RigStore(store)` runs the flows over any of rig's `TokenStore`s.
- `FileTokenStore` and `MemoryTokenStore` implement rig's `TokenStore` too,
  so one store serves this crate and rig's own authenticators.
- `chatgpt_config(token)` is an `OpenAIConfig` that sends what
  api.openai.com accepts with a ChatGPT token (below), and
  `chatgpt_dialect()` is its dialect.

```rust
use model_signin::rig::chatgpt_config;

let token = chatgpt.access_token().await?.ok_or("not signed in")?;
let reply = chatgpt_config(token).client().responses("gpt-6-luna").call(request).await?;
```

Without the feature, the crate does not depend on rig-core.

## Who may use Sign in with ChatGPT

OpenAI documents the flow for third-party apps, but at launch plan usage is
for "open-source projects, personal projects that run locally, and selected
private apps". A paid or remotely hosted app joins OpenAI's waitlist before
offering it ([Sign in with ChatGPT](https://developers.openai.com/siwc)).
Read OpenAI's terms before you ship it. OpenRouter's PKCE flow is meant for
any third-party app.

## Calling the Responses API with the ChatGPT token

The token is a bearer for `https://api.openai.com/v1/responses`, which holds
it to rules an API key is not held to. OpenAI requires `store: false` and
`stream: true` on every request, and says not to send the token to ChatGPT's
`backend-api` endpoints. Measured on 2026-10-25:

| A request with the token | What api.openai.com answers |
| --- | --- |
| `stream: false` (rig's `call()` on the OpenAI dialect) | `400 {"detail":"Stream must be set to true"}` |
| `input` as a string | `400 {"detail":"Input must be a list"}` |
| `stream: true`, `input` a list | `200`, an event stream sent **with no `Content-Type`**, which rig's stream reader refuses unless the wire opts in |

pi also leaves out `max_output_tokens`, `temperature` and the prompt-cache
retention fields. rig already has all of this as its Codex contract
(`ResponsesContract::Codex`), which it uses only for the Codex backend. That
contract always streams, accepts the unlabelled reply, forces
`store: false`, and drops the sampling, output-cap and structured-output
fields. `model_signin::rig::chatgpt_dialect` copies rig's OpenAI dialect,
keeps its base URL `https://api.openai.com/v1`, and sets the contract to
Codex. rig then sends
`model`, `input`, `stream: true`, `store: false` and
`include: ["reasoning.encrypted_content"]`, and nothing else.

Two more things OpenAI documents for these tokens:

- `GET /v1/models` returns a `models` array keyed by `slug`, not the usual
  `data` list.
- A usage limit arrives as `response.failed` with
  `subscription_sharing_usage_limit_exceeded` or
  `subscription_sharing_usage_unavailable`.

## Where it departs from pi

- **State before anything else.** A callback whose `state` is missing or
  different is refused and the sign-in keeps waiting. A callback with this
  sign-in's state ends it, so its `error`, or a missing code or client id,
  fails the sign-in at once. pi answers those with a 400 and keeps waiting,
  and honours `error` without checking `state`.
- **The page tells the truth.** The browser gets its page after the token
  exchange, so it says whether the credential was stored. pi's ChatGPT
  listener says "completed" before it exchanges the code.
- **No pasted redirect URL.** pi also accepts the final URL pasted into a
  prompt, for a browser on another machine. This crate has no prompt.
- **An in-process lock as well as the store's.** A refresh takes both, as
  rig's authenticators do, so a store whose lock holds nothing
  (`MemoryTokenStore`) still refreshes once.
- **No redirects.** The token and key requests follow none, so a 307 or
  308 cannot take a code, its verifier or a refresh token to another
  host: a 3xx fails the request. pi's `fetch` follows them with the body.
  A refused token request also quotes only the OAuth `error` and
  `error_description`, where pi quotes the whole body.

## Requirements

- **Rust 1.97.1 or later**, which rig-core 0.45 needs. `rust-toolchain.toml`
  pins it.
- **serde_json's `preserve_order`, with `rig`.** rig-core turns this feature on. In a
  Cargo workspace, feature unification turns it on for every crate there
  that builds alongside this one. Their `serde_json` objects then keep
  insertion order instead of sorting their keys, so output that depends on
  key order can change with how the workspace is built.

## The examples

With [just](https://just.systems), from the repository root:

```bash
just example   # the web example: opens http://127.0.0.1:3000
just sign-in   # the terminal example
just           # every recipe
```

Both keep credentials in `~/.model-signin`, or `$MODEL_SIGNIN_DIR`, and
`just sign-out` deletes them. Without just:

`cargo run --features rig --example sign-in -- --dir <dir> --agent-name <name>`
signs in to both providers for real from the terminal and makes one call
through each with rig. Each sign-in opens its page in the browser.
`openrouter` or `chatgpt` limits it to one provider, and `--again` signs in
again.

`examples/web` does the same from a browser, on
[Topcoat](https://github.com/tokio-rs/topcoat). It runs OpenRouter's flow
from its own routes (`start`, then `finish` from
`/openrouter/callback/{flow}`), starts a ChatGPT sign-in and waits for it in
a task, and sends a prompt through rig to either provider. The reply streams
into the page as the model writes it, with no reload: a Topcoat shard
renders again, and a `live!` region in it emits each fragment. It is its
own package because Topcoat needs Rust 1.99, and it needs `topcoat-cli` to
bundle Topcoat's runtime script; `just example` installs that under
`examples/web/target` the first time.

```bash
cargo install topcoat-cli --version 0.11.0 --locked
cd examples/web && topcoat asset bundle && cargo run -- --dir <dir> [--agent-name <name>] [--no-open]
```

## Development

`just check` runs everything CI runs. One at a time:

```bash
cargo fmt --check
```

```bash
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --all-features --locked -- -D warnings
```

```bash
cargo deny check
```

```bash
cargo nextest run --locked
cargo nextest run --all-features --locked
```

CI runs them on Linux, macOS and Windows. The tests run both flows against a
fake auth server that checks PKCE and rotates refresh tokens. They cover:

- a wrong verifier, a mismatched state, a missing issued client id, and a
  missing scope or ID token
- two processes refreshing at once (two stores over one directory), which
  refresh once
- a refresh whose caller gives up, which still saves the rotated token
- a taken port, and the idle connections a finished sign-in closes
- OpenRouter's exchange errors and expired flows
- a token or key endpoint that redirects: the request fails, and the
  other host gets nothing
- with `rig`: this crate's file store and rig's over one directory, which
  refresh once and hold one lock

## Credits

The flows follow pi ([earendil-works/pi](https://github.com/earendil-works/pi),
MIT, © 2025 Mario Zechner) at commit
`d5b3de22d0e24a3e9c38a9410d3329b099717283`, closely enough that most error
messages are pi's. Nothing is taken from OpenAI's DevKit.

## License

MIT, with pi's notice for the ported flows and rig's for the ported token stores: [LICENSE](LICENSE).
