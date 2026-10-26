//! Signs in to OpenRouter and to ChatGPT for real, then makes one call
//! through each with rig:
//!
//! ```text
//! cargo run --features rig --example sign-in -- --dir <dir> [--agent-name <name>]
//!     [openrouter|chatgpt] [--again] [--openrouter-model <id>] [--chatgpt-model <id>]
//! ```
//!
//! Each sign-in opens its page in the browser; finish it there. A provider
//! already signed in is not asked again unless `--again` is given. The
//! credentials go to `--dir`: 0600 files in a 0700 directory, created on
//! first use. A ChatGPT sign-in needs `--agent-name`, the name OpenAI shows
//! on its consent page. No token is printed.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use model_signin::rig::chatgpt_config;
use model_signin::{ChatGpt, FileTokenStore, OpenRouter, device_id, now};
use rig_core::completion::CompletionRequest;
use rig_core::providers::openrouter;

const PROMPT: &str = "In one short sentence, what is OAuth PKCE?";
const USAGE: &str = "usage: sign-in --dir <dir> [--agent-name <name>] [openrouter|chatgpt] \
                     [--again] [--openrouter-model <id>] [--chatgpt-model <id>]";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    // Display, not Debug: a provider error's Debug carries its response headers.
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut flags = HashMap::new();
    let (mut again, mut only) = (false, None);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--again" => again = true,
            "--dir" | "--agent-name" | "--openrouter-model" | "--chatgpt-model" => {
                flags.insert(arg, args.next().ok_or(USAGE)?);
            }
            "openrouter" | "chatgpt" if only.is_none() => only = Some(arg),
            _ => return Err(USAGE.into()),
        }
    }
    let dir = PathBuf::from(flags.remove("--dir").ok_or(USAGE)?);
    println!("credentials: {}", dir.display());
    let store = FileTokenStore::new(&dir);
    if only.as_deref() != Some("chatgpt") {
        let model = flags.remove("--openrouter-model");
        let model = model.unwrap_or("openai/gpt-6-luna".into());
        with_openrouter(&store, again, &model).await?;
    }
    if only.as_deref() != Some("openrouter") {
        let model = flags
            .remove("--chatgpt-model")
            .unwrap_or("gpt-6-luna".into());
        let agent_name = flags.remove("--agent-name");
        with_chatgpt(&store, &dir, again, &model, agent_name).await?;
    }
    Ok(())
}

async fn with_openrouter(store: &FileTokenStore, again: bool, model: &str) -> Result<()> {
    let openrouter = OpenRouter::new(store.clone());
    if again || openrouter.credential().await?.is_none() {
        let sign_in = openrouter.sign_in().await?;
        open("OpenRouter", sign_in.url());
        sign_in.finish().await?;
        println!("OpenRouter: signed in; the key is stored");
    }
    let status = openrouter.key_status().await?.ok_or("no OpenRouter key")?;
    let limit = status
        .limit
        .map_or("none".into(), |limit| format!("${limit}"));
    println!(
        "OpenRouter: GET /api/v1/key accepts the key (usage ${:.4}, limit {limit})",
        status.usage
    );
    let key = openrouter
        .credential()
        .await?
        .ok_or("no OpenRouter key")?
        .access;
    let reply = openrouter::new(key)
        .completion(model)
        .call(CompletionRequest::new(PROMPT))
        .await?;
    println!("OpenRouter, {model}: {}", reply.text().trim());
    Ok(())
}

async fn with_chatgpt(
    store: &FileTokenStore,
    dir: &Path,
    again: bool,
    model: &str,
    agent_name: Option<String>,
) -> Result<()> {
    let chatgpt = ChatGpt::new(store.clone(), agent_name.clone().unwrap_or_default());
    if again || chatgpt.credential().await?.is_none() {
        if agent_name.is_none() {
            return Err(
                "a ChatGPT sign-in needs --agent-name, the name OpenAI shows the user".into(),
            );
        }
        let sign_in = chatgpt.sign_in(&device_id(dir)?).await?;
        open("ChatGPT", sign_in.url());
        let credential = sign_in.finish().await?;
        println!(
            "ChatGPT: signed in; scopes {}; refreshed {} minutes from now",
            credential.scopes.unwrap_or_default().join(" "),
            (credential.expires - now() - 5 * 60_000) / 60_000
        );
    }
    let token = chatgpt
        .access_token()
        .await?
        .ok_or("not signed in to ChatGPT")?;
    // rig's OpenAI dialect on its Codex contract: what api.openai.com
    // accepts with a ChatGPT token.
    let reply = chatgpt_config(token)
        .client()
        .responses(model)
        .call(CompletionRequest::new(PROMPT))
        .await?;
    println!(
        "ChatGPT, {model} on api.openai.com/v1/responses: {}",
        reply.text().trim()
    );
    let echoed: Vec<String> = [
        "store",
        "max_output_tokens",
        "temperature",
        "prompt_cache_key",
    ]
    .iter()
    .filter_map(|field| Some(format!("{field}={}", reply.raw.get(field)?)))
    .collect();
    if !echoed.is_empty() {
        println!("ChatGPT: the response records {}", echoed.join(", "));
    }
    Ok(())
}

fn open(provider: &str, url: &str) {
    println!("{provider}: finish signing in on the page the browser opens:\n  {url}");
    let mut opener = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        // Not `cmd /c start`: cmd would split the URL at its `&`s.
        let mut rundll = Command::new("rundll32.exe");
        rundll.arg("url.dll,FileProtocolHandler");
        rundll
    } else {
        Command::new("xdg-open")
    };
    if opener.arg(url).status().is_err() {
        println!("{provider}: no browser opened; open the page above yourself");
    }
}
