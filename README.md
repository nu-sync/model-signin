# model-signin

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/model-signin.svg?style=flat-square
[crates-url]: https://crates.io/crates/model-signin
[docs-badge]: https://img.shields.io/docsrs/model-signin?style=flat-square
[docs-url]: https://docs.rs/model-signin
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
[mit-url]: https://github.com/nu-sync/model-signin/blob/main/LICENSE
[actions-badge]: https://img.shields.io/github/actions/workflow/status/nu-sync/model-signin/ci.yml?branch=main&style=flat-square
[actions-url]: https://github.com/nu-sync/model-signin/actions?query=branch%3Amain

Let your users sign in to **ChatGPT** or **OpenRouter** from a Rust app, and
call models on their account instead of yours.

model-signin runs the OAuth sign-in, stores the credential, and refreshes it.
You get a token or an API key to use with any HTTP client or model library.
An optional connector, the `rig` feature, plugs it into
[rig](https://github.com/0xPlaygrounds/rig).

**Early-stage. Expect breaking changes before 1.0.**

```toml
[dependencies]
model-signin = "0.1"
```

```rust,ignore
use model_signin::{ChatGpt, FileTokenStore, device_id};

let dir = std::path::Path::new(".credentials");
let chatgpt = ChatGpt::new(FileTokenStore::new(dir), "My App");

if chatgpt.credential().await?.is_none() {
    let sign_in = chatgpt.sign_in(&device_id(dir)?).await?;
    println!("Open {}", sign_in.url());
    sign_in.finish().await?; // waits for the user to approve
}

// A token with at least five minutes left, refreshed if needed.
let token = chatgpt.access_token().await?.ok_or("not signed in")?;
```

## Sign in with ChatGPT

The user approves your app on OpenAI's page. OpenAI redirects back to a
listener on `127.0.0.1:1455`, which lives only while the sign-in waits. The
token is a bearer for `https://api.openai.com/v1`.

Without more setup, that listener shows "ChatGPT is connected" once the
sign-in ends. To send the browser back to your app instead, set
`return_to`:

```rust,ignore
let chatgpt = ChatGpt::new(store, "My App").return_to("http://127.0.0.1:3000/");
```

OpenAI's Sign in with ChatGPT is open to "open-source projects, personal
projects that run locally, and selected private apps". A paid or hosted app
joins OpenAI's waitlist first. Read
[OpenAI's terms](https://developers.openai.com/siwc) before you ship it.

## OpenRouter

OpenRouter's [OAuth PKCE](https://openrouter.ai/docs/use-cases/oauth-pkce)
gives your app a permanent API key on the user's account. Run it from your
own HTTP server:

```rust,ignore
use model_signin::{FileTokenStore, OpenRouter};

let openrouter = OpenRouter::new(FileTokenStore::new(".credentials"));

// In the route that starts a sign-in: send the browser to this URL.
let url = openrouter.start("https://app.example/openrouter/callback");

// In GET /openrouter/callback/{flow}?code=…
let credential = openrouter.finish(&flow, &code).await?;
```

Or, from a program without a server, behind a temporary local listener:

```rust,ignore
let sign_in = openrouter.sign_in().await?;
println!("Open {}", sign_in.url());
sign_in.finish().await?;
```

## Storage

Credentials live in a `TokenStore`:

- `FileTokenStore` keeps one owner-only file per provider and locks it
  across processes, so two copies of your app refresh once.
- `MemoryTokenStore` keeps them in memory.
- Implement `TokenStore` to keep them in a keychain or a database.

The stored JSON matches [pi](https://github.com/earendil-works/pi)'s, so pi
can read it too. No token appears in `Debug` output, logs or error messages.

## With rig

```toml
model-signin = { version = "0.1", features = ["rig"] }
```

api.openai.com only accepts a ChatGPT token on streamed requests with
`store: false`. `chatgpt_config` sets up rig's OpenAI client to send those:

```rust,ignore
use model_signin::rig::chatgpt_config;

let token = chatgpt.access_token().await?.ok_or("not signed in")?;
let reply = chatgpt_config(token)
    .client()
    .responses("gpt-6-luna")
    .stream(request)?;
```

The stores work with rig as well: `FileTokenStore` and `MemoryTokenStore`
implement rig's `TokenStore`, and `RigStore` wraps any rig store for this
crate. Without the feature, model-signin does not depend on rig.

## Examples

With [just](https://just.systems):

```bash
just example   # a web app: both sign-ins, then a streamed reply
just sign-in   # the same from the terminal
```

Both keep credentials in `~/.model-signin` (or `$MODEL_SIGNIN_DIR`).
`just sign-out` deletes them. The web example is built on
[Topcoat](https://github.com/tokio-rs/topcoat) and needs Rust 1.99; `just
example` installs what it needs on the first run.

## Learn more

- [API docs](https://docs.rs/model-signin)
- [How it works](docs/how-it-works.md): what each flow sends, the storage
  format, what api.openai.com expects from a ChatGPT token, and where this
  crate departs from pi.
- [Upstreaming to rig](docs/UPSTREAM.md): what moving this into rig would
  take.
- Contributing: `just check` runs what CI runs. [AGENTS.md](AGENTS.md) lists
  the rules a change must keep.

## Credits

The sign-in and refresh logic follows
[pi](https://github.com/earendil-works/pi) (MIT, © 2025 Mario Zechner), and
the token stores follow [rig](https://github.com/0xPlaygrounds/rig)'s (MIT).

## License

[MIT](LICENSE)
