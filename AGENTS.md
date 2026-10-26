# AGENTS.md

model-signin: Sign in with ChatGPT and OpenRouter's OAuth PKCE for Rust
apps, ported from pi (`earendil-works/pi` at `d5b3de22`). Generic over a
`TokenStore`; the optional `rig` feature connects it to rig-core.
[README.md](README.md) describes the flows; [docs/UPSTREAM.md](docs/UPSTREAM.md)
describes how it would move into rig.

## Commands

`just check` runs all of these plus the web example's checks; `just` lists
every recipe, and `justfile` is the command surface to extend. Run them
before calling a change done. CI runs them on Linux,
macOS and Windows, with and without `rig`.

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo deny --log-level error check
cargo nextest run --locked
cargo nextest run --all-features --locked
```

The toolchain is pinned in `rust-toolchain.toml` (1.97.1).

`examples/web` (Topcoat) is a separate package with its own workspace,
lockfile and toolchain (1.99.1, which Topcoat 0.11 needs). Root commands
don't build it. Check it from inside that directory:

```bash
cd examples/web && cargo fmt --check && cargo clippy --locked -- -D warnings
```

Both examples sign in for real and need a browser and both accounts, so
don't finish a sign-in in an unattended session. To smoke-test the web
example, run `PORT=<free port> MODEL_SIGNIN_DIR=<scratch dir> just example --no-open`
(a person's own copy may hold 3000, with real credentials) and curl its routes; the sign-in routes answer with a 303
to the provider.

## Layout

| Path | What it holds |
| --- | --- |
| `src/lib.rs` | Re-exports, `Error`, and the no-redirect HTTP client |
| `src/chatgpt.rs` | Sign in with ChatGPT and its refresh (pi `openai-chatgpt.ts`, `auth/resolve.ts`) |
| `src/openrouter.rs` | OpenRouter PKCE: `start`/`finish` for an app's server, `sign_in` over loopback |
| `src/loopback.rs` | The callback listener, alive only while a sign-in waits |
| `src/pkce.rs` | Verifier, challenge, random values, UUIDs |
| `src/credential.rs` | pi's `OAuthCredential` JSON |
| `src/store.rs` | `TokenStore`, `StoreLock`, `MemoryTokenStore`, `FileTokenStore` (ported from rig-core 0.45.0) |
| `src/rig.rs` | `rig` feature only: store adapters both ways, `chatgpt_dialect`, `chatgpt_config` |
| `examples/sign-in.rs` | Terminal example: both sign-ins, then one rig call each (`--features rig`) |
| `examples/web/` | Topcoat example, its own package: sign-ins from a browser, then a reply streamed through a shard and `live!` region. Needs `topcoat asset bundle` after each build (`just example` does it) |
| `tests/signin.rs` | Both flows against a fake auth server (axum) that checks PKCE and rotates refresh tokens |

## Rules

These are invariants. Breaking one is a bug, even if the tests pass.

- **Never expose a token.** No logging, printing or `Debug` output of an access token, refresh token, key,
  code or verifier. `Credential`'s `Debug` leaves them out. Error messages
  quote only the provider's OAuth `error`/`error_description` or an HTTP
  status, never a response body. serde errors on a stored record report
  line and column only.
- **No redirects on auth requests.** Build every request through
  `http_client()`, which follows no redirects. A 3xx must fail the request so a code,
  verifier or refresh token never reaches another host. A test covers this.
- **A started refresh runs to completion.** OpenAI rotates refresh tokens, so the
  refresh and its save run in a spawned task bounded by a timeout, never
  by the caller's future. Only waiting for the locks may be cancelled. Take the
  in-process lock first, then the store's lock, then re-read the credential before
  refreshing.
- **pi compatibility.** Credentials are pi's JSON under pi's provider ids
  (`openai`, `openrouter`). Keep field names, `expires` in epoch
  milliseconds, `NEVER` for OpenRouter, and pi's error messages. When you
  depart from pi on purpose, add it to README's "Where it departs from pi".
- **The core stays generic.** Nothing outside `src/rig.rs` may name
  `rig_core`, and that module stays behind `#[cfg(feature = "rig")]`.
  `FileTokenStore` has to keep reading and locking the same files as
  rig's (`<dir>/<key>.json`, `<dir>/<key>.lock`, 0600 files in 0700
  directories). The `rig` test checks this.
- **rig-core stays within one minor version** (`0.45`). Moving to a new minor means re-checking
  `src/store.rs` against rig's `providers/internal/auth/store.rs` and the
  dialect fields `src/rig.rs` sets.
- **Dependencies:** `cargo deny` allows permissive licenses and crates.io only.
  Explain each new dependency in a `Cargo.toml` comment, as the existing ones are.
- **Lints:** `unsafe_code` is forbidden, and `dbg!` and `todo!` are denied.

## Style

- Doc comments are short and state behavior. Write "refreshed with five minutes left",
  not "this function handles refreshing". Code comments explain *why*.
  Match the existing tone.
- Tests call the public API the way an app would, against the fake server, and
  assert what the user sees: the stored JSON, error text, file modes.
  A test that runs two `FileTokenStore`s over one directory stands in for two processes.
- When behavior changes, update README.md in the same change, and
  docs/UPSTREAM.md if the change affects what rig would need.
