# model-signin's commands. `just` lists them.

# Where the examples keep credentials: 0600 files in a 0700 directory,
# outside the repository so no token is ever committed.
credentials := env("MODEL_SIGNIN_DIR", home_directory() / ".model-signin")

# List the recipes.
default:
    @just --list

# Run the Topcoat web example at http://127.0.0.1:3000 (or $PORT) and open it (args: --agent-name <name>, --no-open).
[positional-arguments]
example *args: web-toolchain web-cli
    cd examples/web && target/tools/bin/topcoat asset bundle && cargo run -- --dir "{{ credentials }}" "$@"

# Run the terminal example: sign in to both providers, then one rig call each.
[positional-arguments]
sign-in *args:
    cargo run --features rig --example sign-in -- --dir "{{ credentials }}" --agent-name "model-signin example" "$@"

# Run every check CI runs: the library with and without rig, and the web example.
check: fmt-check lint deny test web-check

# Format the library, the web example and this justfile.
fmt:
    cargo fmt
    cd examples/web && cargo fmt
    just --fmt --unstable

# Check formatting without changing anything.
fmt-check:
    cargo fmt --check
    just --fmt --check --unstable

# Lint the library with and without the rig feature.
lint:
    cargo clippy --all-targets --locked -- -D warnings
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Check licenses, advisories and sources.
deny:
    cargo deny --log-level error check

# Run the tests with and without the rig feature.
test:
    cargo nextest run --locked
    cargo nextest run --all-features --locked

# Format-check and lint the web example on its own toolchain.
web-check: web-toolchain
    cd examples/web && cargo fmt --check && cargo clippy --locked -- -D warnings

# Forget both examples' stored credentials. An OpenRouter key stays valid until revoked at openrouter.ai.
sign-out:
    rm -f "{{ credentials }}/openai.json" "{{ credentials }}/openrouter.json"

# Install topcoat-cli 0.11.0 under examples/web/target, which bundles the runtime script the page loads.
[private]
web-cli: web-toolchain
    @cd examples/web && (test -x target/tools/bin/topcoat || cargo install topcoat-cli --version 0.11.0 --locked --root target/tools)

# Install the web example's Rust (1.99.1) if rustup lacks it.
[private]
web-toolchain:
    @cd examples/web && (rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install)
