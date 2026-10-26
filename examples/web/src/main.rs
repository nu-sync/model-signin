//! Both sign-ins from a browser, then a prompt through rig, served by
//! Topcoat at http://127.0.0.1:3000 (or `PORT`):
//!
//! ```text
//! just example                     # from the repository root, or:
//! cd examples/web && cargo run -- --dir <dir> [--agent-name <name>] [--no-open]
//! ```
//!
//! OpenRouter runs from this server's own routes: `start` sends the browser
//! to OpenRouter, and `/openrouter/callback/{flow}` finishes the sign-in.
//! Sign in with ChatGPT always calls back to its own listener on
//! 127.0.0.1:1455, so this server starts the sign-in, sends the browser on,
//! and waits for it in a task; the ChatGPT card is a `live!` region that
//! streams the outcome when it ends. Sending a prompt renders only the reply
//! shard again, whose `live!` region streams the reply as the model writes
//! it, with no reload. Both need
//! Topcoat's runtime script, which `topcoat asset bundle` writes next to the
//! binary; `just example` runs it.
//! Credentials go to `--dir`, as in the `sign-in` example. No token reaches
//! a page or the log.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::StreamExt;
use model_signin::rig::chatgpt_config;
use model_signin::{ChatGpt, FileTokenStore, OpenRouter, device_id};
use rig_core::completion::CompletionRequest;
use rig_core::providers::openrouter;
use rig_core::streaming::{CompletionStream, Item, StreamEvent};
use tokio::sync::watch;
use topcoat::{
    Result,
    asset::{AssetBundle, RouterBuilderAssetExt},
    context::{Cx, app_context},
    router::{
        Router, RouterService,
        error::{SeeOther, see_other},
        href, page, path_param, query_params, route,
    },
    runtime::{Event, RouterBuilderRuntimeExt, record, shard, signal},
    view::{View, component, emit, live, view},
};

const OPENROUTER_MODEL: &str = "openai/gpt-6-luna";
const CHATGPT_MODEL: &str = "gpt-6-luna";
const PROMPT: &str = "In one short sentence, what is OAuth PKCE?";
const USAGE: &str = "usage: model-signin-web --dir <dir> [--agent-name <name>] [--no-open]";

/// Shared by every request.
struct App {
    dir: PathBuf,
    /// Where this server listens, as `http://127.0.0.1:<port>`.
    origin: String,
    openrouter: OpenRouter,
    chatgpt: ChatGpt,
    // Shared with the task that waits for a ChatGPT sign-in.
    notes: Arc<Mutex<Notes>>,
    /// Whether a ChatGPT sign-in is waiting; its task, or Cancel, clears it.
    chatgpt_waiting: watch::Sender<bool>,
}

/// What the page shows once, besides each provider's state.
#[derive(Default)]
struct Notes {
    notice: Option<Notice>,
    chatgpt_pending: Option<Pending>,
}

/// A ChatGPT sign-in waiting for its callback.
struct Pending {
    /// The authorize page, to open again if its tab was closed.
    url: String,
    /// Its task; aborting it closes the listener on 1455.
    task: tokio::task::AbortHandle,
}

/// The outcome of the last sign-in or sign-out.
struct Notice {
    ok: bool,
    text: String,
}

fn lock(notes: &Mutex<Notes>) -> MutexGuard<'_, Notes> {
    notes.lock().unwrap_or_else(|e| e.into_inner())
}

impl App {
    fn notes(&self) -> MutexGuard<'_, Notes> {
        lock(&self.notes)
    }

    fn done(&self, text: impl Into<String>) {
        self.notes().notice = Some(Notice {
            ok: true,
            text: text.into(),
        });
    }

    fn failed(&self, text: impl Into<String>) {
        self.notes().notice = Some(Notice {
            ok: false,
            text: text.into(),
        });
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (mut dir, mut agent_name) = (None, "model-signin web example".to_owned());
    let mut open_browser = true;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => dir = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            "--agent-name" => agent_name = args.next().ok_or(USAGE)?,
            "--no-open" => open_browser = false,
            _ => return Err(USAGE.into()),
        }
    }
    let dir = dir.ok_or(USAGE)?;
    // The runtime's browser script, which `topcoat asset bundle` writes next
    // to the binary.
    let assets = AssetBundle::load().map_err(|e| {
        format!("no asset bundle ({e}); run `just example`, or `topcoat asset bundle` first")
    })?;
    // PORT, as Topcoat's own `start` reads it.
    let port: u16 = match std::env::var("PORT") {
        Ok(port) => port.parse().map_err(|_| "PORT must be a port number")?,
        Err(_) => 3000,
    };
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        format!("{addr}: {e}; is another copy running? Set PORT to use another port")
    })?;
    let origin = format!("http://{addr}");
    println!("credentials: {}\nopen {origin}", dir.display());
    if open_browser {
        open(&origin);
    }
    let store = FileTokenStore::new(&dir);
    let app = App {
        openrouter: OpenRouter::new(store.clone()),
        // After approving, OpenAI's redirect to 1455 sends the browser on to here.
        chatgpt: ChatGpt::new(store, agent_name).return_to(format!("{origin}/")),
        dir,
        origin,
        notes: Arc::default(),
        chatgpt_waiting: watch::Sender::new(false),
    };
    let router = Router::builder()
        .page(home)
        .route(openrouter_start)
        .route(openrouter_callback)
        .route(openrouter_sign_out)
        .route(chatgpt_start)
        .route(chatgpt_cancel)
        .route(chatgpt_sign_out)
        .route(reply)
        .app_context(app)
        .assets(assets)
        .runtime()
        .build();
    // A page waiting for a ChatGPT sign-in holds its response open, so a
    // graceful stop gets two seconds, and a second Ctrl+C stops at once.
    let service = RouterService::new(router).shutdown_timeout(Duration::from_secs(2));
    topcoat::serve_until(listener, service, stop_requested()).await?;
    Ok(())
}

/// Ctrl+C or SIGTERM. After it, another Ctrl+C exits without waiting.
async fn stop_requested() {
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => drop(signal.recv().await),
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    println!("stopping; Ctrl+C again to stop now");
    tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
        std::process::exit(130);
    });
}

/// A provider's sign-in state, as its card shows it.
enum State {
    SignedIn(Vec<(&'static str, String)>),
    SignedOut,
    /// Waiting for approval at this authorize page.
    Waiting(String),
    Failed(String),
}

impl State {
    fn badge(&self) -> (&'static str, &'static str) {
        match self {
            State::SignedIn(_) => ("Signed in", "badge ok"),
            State::SignedOut => ("Not signed in", "badge"),
            State::Waiting(_) => ("Waiting for approval", "badge wait"),
            State::Failed(_) => ("Error", "badge error"),
        }
    }
}

async fn openrouter_state(app: &App) -> State {
    match app.openrouter.key_status().await {
        Ok(Some(status)) => State::SignedIn(vec![
            ("Usage", format!("${:.4}", status.usage)),
            (
                "Limit",
                status
                    .limit
                    .map_or("None".into(), |limit| format!("${limit}")),
            ),
        ]),
        Ok(None) => State::SignedOut,
        Err(error) => State::Failed(format!("The stored key failed: {error}")),
    }
}

async fn chatgpt_state(app: &App) -> State {
    if let Some(pending) = &app.notes().chatgpt_pending {
        return State::Waiting(pending.url.clone());
    }
    match app.chatgpt.credential().await {
        Ok(Some(credential)) => {
            // The flow refreshes the token once less than five minutes are left.
            let minutes = (credential.expires - model_signin::now() - 5 * 60_000) / 60_000;
            let refresh = match minutes {
                ..=0 => "On next use".into(),
                1..60 => format!("In {minutes} min"),
                _ => format!("In {} h {} min", minutes / 60, minutes % 60),
            };
            State::SignedIn(vec![
                ("Token refresh", refresh),
                ("Scopes", credential.scopes.unwrap_or_default().join(" ")),
            ])
        }
        Ok(None) => State::SignedOut,
        Err(error) => State::Failed(format!("The stored credential failed: {error}")),
    }
}

#[page("/")]
async fn home(cx: &Cx) -> Result<impl View> {
    let app = app_context::<App>(cx);
    let openrouter = openrouter_state(app).await;
    let chatgpt = chatgpt_state(app).await;
    let notice = app.notes().notice.take();
    let models = [
        ("openrouter", "OpenRouter", OPENROUTER_MODEL, &openrouter),
        ("chatgpt", "ChatGPT", CHATGPT_MODEL, &chatgpt),
    ]
    .into_iter()
    .filter(|(_, _, _, state)| matches!(state, State::SignedIn(_)))
    .map(|(value, name, model, _)| (value.to_owned(), format!("{name} · {model}")))
    .collect::<Vec<_>>();
    let chatgpt_waiting = matches!(chatgpt, State::Waiting(_));
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>"model-signin"</title>
                topcoat::runtime::script()
                <style>(STYLE)</style>
            </head>
            <body>
                <main>
                    <header>
                        <h1>"model-signin"</h1>
                        <p class="muted">"Credentials in " <code>(app.dir.display().to_string())</code></p>
                    </header>

                    if chatgpt_waiting {
                        // The sign-in's outcome, streamed once its task records it.
                        (live! {
                            let mut waiting = app.chatgpt_waiting.subscribe();
                            emit! {}?;
                            let _ = waiting.wait_for(|waiting| !waiting).await;
                            let notice = app.notes().notice.take();
                            emit! { notice_view(notice: notice) }
                        })
                    } else {
                        notice_view(notice: notice)
                    }

                    <div class="providers">
                        card(
                            name: "OpenRouter",
                            state: openrouter,
                            sign_in: href!(openrouter_start).resolve(cx),
                            sign_out: href!(openrouter_sign_out).resolve(cx),
                        )
                        if chatgpt_waiting {
                            // Streams the finished card when the sign-in ends.
                            (live! {
                                let mut waiting = app.chatgpt_waiting.subscribe();
                                emit! { chatgpt_card(state: chatgpt) }?;
                                let _ = waiting.wait_for(|waiting| !waiting).await;
                                let state = chatgpt_state(app).await;
                                emit! { chatgpt_card(state: state) }
                            })
                        } else {
                            chatgpt_card(state: chatgpt)
                        }
                    </div>

                    ask(models: models)
                </main>
            </body>
        </html>
    })
}

#[component]
async fn notice_view(notice: Option<Notice>) -> Result<impl View> {
    Ok(view! {
        match notice {
            Some(Notice { ok: true, text }) => <p class="notice ok" role="status">(text)</p>,
            Some(Notice { ok: false, text }) => <p class="notice error" role="alert">(text)</p>,
            None => {}
        }
    })
}

#[component]
async fn chatgpt_card(cx: &Cx, state: State) -> Result<impl View> {
    Ok(view! {
        card(
            name: "ChatGPT",
            state: state,
            sign_in: href!(chatgpt_start).resolve(cx),
            sign_out: href!(chatgpt_sign_out).resolve(cx),
        )
    })
}

/// One provider: its state, and the one action that state allows.
#[component]
async fn card(
    cx: &Cx,
    name: &'static str,
    state: State,
    sign_in: String,
    sign_out: String,
) -> Result<impl View> {
    let (badge, badge_class) = state.badge();
    Ok(view! {
        <section class="card" aria-label=(name)>
            <div class="card-head">
                <h2>(name)</h2>
                <span class=(badge_class)>(badge)</span>
            </div>
            match state {
                State::SignedIn(details) => {
                    <dl>
                        for (term, value) in details {
                            <div>
                                <dt>(term)</dt>
                                <dd>(value)</dd>
                            </div>
                        }
                    </dl>
                    <form method="post" action=(sign_out)>
                        <button class="secondary">"Sign out"</button>
                    </form>
                }
                State::SignedOut => {
                    <form method="post" action=(sign_in)>
                        <button>"Sign in with " (name)</button>
                    </form>
                }
                State::Waiting(url) => {
                    <div class="actions">
                        <a class="button" href=(url)>"Continue sign-in"</a>
                        <form method="post" action=(href!(chatgpt_cancel).resolve(cx))>
                            <button class="secondary">"Cancel"</button>
                        </form>
                    </div>
                }
                State::Failed(error) => {
                    <p class="error-text">(error)</p>
                    <form method="post" action=(sign_in)>
                        <button>"Sign in again"</button>
                    </form>
                }
            }
        </section>
    })
}

/// A prompt the browser sent. `n` counts sends, so sending the same prompt
/// again still changes the value and renders a new reply.
#[record]
#[derive(Clone)]
struct Sent {
    n: u64,
    provider: String,
    prompt: String,
}

/// The prompt form. Sending changes the `sent` signal, which renders only
/// the [`reply`] shard again; the page does not reload.
#[component]
async fn ask(cx: &Cx, models: Vec<(String, String)>) -> Result<impl View> {
    let first = models
        .first()
        .map(|(value, _)| value.clone())
        .unwrap_or_default();
    let provider = signal(cx, move || first);
    let prompt = signal(cx, || PROMPT.to_owned());
    let sent = signal(cx, || Sent {
        n: 0,
        provider: String::new(),
        prompt: String::new(),
    });
    let none_signed_in = models.is_empty();
    Ok(view! {
        <section class="card" aria-label="Ask">
            <h2>"Ask"</h2>
            <form
                class="ask"
                @submit=$(|e: Event| {
                    e.prevent_default();
                    sent.set(Sent {
                        n: sent.get().n + 1u64,
                        provider: provider.get(),
                        prompt: prompt.get(),
                    });
                })
            >
                <fieldset disabled=(none_signed_in)>
                    <label>
                        "Model"
                        <select name="provider" @change=$(|e: Event| provider.set(e.target.value))>
                            for (value, label) in models {
                                <option value=(value)>(label)</option>
                            }
                        </select>
                    </label>
                    <label>
                        "Prompt"
                        <textarea
                            name="prompt"
                            rows="3"
                            required=(true)
                            @input=$(|e: Event| prompt.set(e.target.value))
                        >
                            (PROMPT)
                        </textarea>
                    </label>
                    <div><button>"Send"</button></div>
                </fieldset>
            </form>
            if none_signed_in {
                <p class="muted">"Sign in to a provider to send a prompt."</p>
            }
            reply(sent: $(sent.get()))
        </section>
    })
}

/// The reply to the last prompt sent, streamed as the model writes it. A
/// newer prompt aborts this render, and with it the model's stream.
#[shard]
async fn reply(cx: &Cx, sent: Sent) -> Result<impl View> {
    let app = app_context::<App>(cx);
    let (name, model) = match sent.provider.as_str() {
        "openrouter" => ("OpenRouter", OPENROUTER_MODEL),
        _ => ("ChatGPT", CHATGPT_MODEL),
    };
    let from = format!("{name} · {model}");
    Ok(view! {
        <div class="reply" aria-live="polite">
            if sent.n > 0 {
                (live! {
                    emit! { <p class="muted">(from.clone())</p><p class="muted">"Thinking…"</p> }?;
                    let mut stream = match open_stream(app, &sent.provider, model, &sent.prompt).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            return emit! { <p class="muted">(from.clone())</p><p class="error-text">(short(&error))</p> };
                        }
                    };
                    let mut text = String::new();
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(Item::Event(StreamEvent::Text { text: fragment, .. })) => {
                                text.push_str(&fragment);
                                emit! { <p class="muted">(from.clone())</p><p>(text.clone())</p> }?;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                return emit! {
                                    <p class="muted">(from.clone())</p>
                                    if !text.is_empty() {
                                        <p>(text.clone())</p>
                                    }
                                    <p class="error-text">(short(&error.to_string()))</p>
                                };
                            }
                        }
                    }
                    emit! { <p class="muted">(from.clone())</p><p>(text.trim().to_owned())</p> }
                })
            }
        </div>
    })
}

/// A provider error without the response body rig's `Display` appends: a
/// body can echo the credential it refused. (Its `Debug` also carries the
/// response headers, so neither is shown whole.)
fn short(error: &str) -> String {
    error.split(": {").next().unwrap_or(error).trim().to_owned()
}

/// Opens a streamed reply to `prompt` from a signed-in provider. The
/// browser picks `provider`, so anything but a signed-in one is refused.
async fn open_stream(
    app: &App,
    provider: &str,
    model: &str,
    prompt: &str,
) -> std::result::Result<CompletionStream, String> {
    let request = CompletionRequest::new(prompt.trim());
    let stream = match provider {
        "openrouter" => {
            let credential = app
                .openrouter
                .credential()
                .await
                .map_err(|e| e.to_string())?;
            let key = credential.ok_or("Sign in to OpenRouter first.")?.access;
            openrouter::new(key).completion(model).stream(request)
        }
        "chatgpt" => {
            let token = app
                .chatgpt
                .access_token()
                .await
                .map_err(|e| e.to_string())?;
            let token = token.ok_or("Sign in to ChatGPT first.")?;
            chatgpt_config(token)
                .client()
                .responses(model)
                .stream(request)
        }
        _ => return Err("Choose a signed-in model.".into()),
    };
    stream.map_err(|e| e.to_string())
}

const STYLE: &str = r#"
:root {
    color-scheme: light;
    --canvas: #f6f6f5; --surface: #ffffff; --text: #1c1c1b; --muted: #6b6b68;
    --border: #e2e2df; --field: #ffffff; --primary: #1c1c1b; --on-primary: #ffffff;
    --focus: #3b6fd8; --ok: #1f7a43; --ok-bg: #e8f4ec; --error: #b3261e; --error-bg: #fbeceb;
    --wait: #8a5a00; --wait-bg: #fbf2df;
    --radius: 10px; --space: 1rem;
    --font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
}
@media (prefers-color-scheme: dark) {
    :root {
        color-scheme: dark;
        --canvas: #141414; --surface: #1c1c1c; --text: #ececea; --muted: #9a9a96;
        --border: #2e2e2c; --field: #161616; --primary: #ececea; --on-primary: #141414;
        --focus: #7aa2f7; --ok: #6cc690; --ok-bg: #16281d; --error: #f2948d; --error-bg: #2f1715;
        --wait: #e3b55c; --wait-bg: #2b2311;
    }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--canvas); color: var(--text); font: 15px/1.5 var(--font); }
main { max-width: 46rem; margin: 0 auto; padding: 2.5rem 1rem 4rem; display: grid; gap: var(--space); }
header { display: grid; gap: .15rem; margin-bottom: .5rem; }
h1 { font-size: 1.5rem; margin: 0; letter-spacing: -.01em; }
h2 { font-size: 1rem; margin: 0; }
p { margin: 0; }
code { font: .85em var(--mono); overflow-wrap: anywhere; }
.muted { color: var(--muted); font-size: .9rem; }
.providers { display: grid; gap: var(--space); grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr)); align-items: start; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
        padding: 1.25rem; display: grid; gap: .9rem; align-content: start; }
.card-head { display: flex; justify-content: space-between; align-items: center; gap: .5rem; }
.badge { font-size: .75rem; font-weight: 600; padding: .15rem .55rem; border-radius: 999px;
         border: 1px solid var(--border); color: var(--muted); white-space: nowrap; }
.badge.ok { color: var(--ok); background: var(--ok-bg); border-color: transparent; }
.badge.wait { color: var(--wait); background: var(--wait-bg); border-color: transparent; }
.badge.error { color: var(--error); background: var(--error-bg); border-color: transparent; }
dl { margin: 0; display: grid; gap: .4rem; }
dl div { display: grid; grid-template-columns: 7rem 1fr; gap: .5rem; }
dt { color: var(--muted); font-size: .85rem; }
dd { margin: 0; font-size: .9rem; overflow-wrap: anywhere; }
@media (max-width: 30rem) { dl div { grid-template-columns: 1fr; gap: 0; } }
.notice { padding: .7rem .9rem; border-radius: var(--radius); font-size: .9rem; }
.notice.ok { background: var(--ok-bg); color: var(--ok); }
.actions { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
.notice.error, .error-text { color: var(--error); }
.notice.error { background: var(--error-bg); }
.error-text { font-size: .9rem; }
fieldset { border: 0; margin: 0; padding: 0; display: grid; gap: .8rem; min-width: 0; }
fieldset:disabled { opacity: .55; }
label { display: grid; gap: .3rem; font-size: .85rem; font-weight: 600; }
select, textarea { font: inherit; font-weight: 400; color: var(--text); background: var(--field);
                   border: 1px solid var(--border); border-radius: 8px; padding: .5rem .65rem; width: 100%; }
textarea { resize: vertical; }
button, a.button { font: inherit; text-decoration: none; display: inline-block; line-height: 1.5; font-weight: 600; cursor: pointer; border-radius: 8px; padding: .5rem .95rem;
         border: 1px solid var(--primary); background: var(--primary); color: var(--on-primary); }
button:hover:not(:disabled), a.button:hover { opacity: .88; }
button:disabled { cursor: default; opacity: .6; }
button.secondary { background: transparent; color: var(--text); border-color: var(--border); }
button.secondary:hover { background: var(--canvas); opacity: 1; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.reply { border-top: 1px solid var(--border); padding-top: .9rem; display: grid; gap: .3rem; white-space: pre-wrap; }
"#;

#[route(POST "/openrouter/sign-in")]
async fn openrouter_start(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    // OpenRouter sends the browser back to <callback>/<flow>.
    let callback = format!("{}/openrouter/callback", app.origin);
    Ok(see_other(app.openrouter.start(&callback)))
}

path_param!(flow);

#[query_params(error = bad_request)]
struct Callback {
    code: Option<String>,
}

#[route(GET "/openrouter/callback/{flow}")]
async fn openrouter_callback(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    let flow = path_param::<Flow>(cx);
    match &query_params::<Callback>(cx)?.code {
        Some(code) => match app.openrouter.finish(flow, code).await {
            Ok(_) => app.done("Signed in to OpenRouter. The key is stored."),
            Err(error) => app.failed(format!("OpenRouter: {error}")),
        },
        None => app.failed("OpenRouter: the callback carried no code"),
    }
    Ok(see_other(href!(home).resolve(cx)))
}

#[route(POST "/openrouter/sign-out")]
async fn openrouter_sign_out(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    match app.openrouter.sign_out().await {
        Ok(()) => app
            .done("Signed out of OpenRouter. The key works until you revoke it at openrouter.ai."),
        Err(error) => app.failed(format!("OpenRouter: {error}")),
    }
    Ok(see_other(href!(home).resolve(cx)))
}

#[route(POST "/chatgpt/sign-in")]
async fn chatgpt_start(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    let started = match device_id(&app.dir) {
        Ok(device) => app.chatgpt.sign_in(&device).await,
        Err(error) => Err(error.into()),
    };
    let sign_in = match started {
        Ok(sign_in) => sign_in,
        Err(error) => {
            app.failed(format!("ChatGPT: {error}"));
            return Ok(see_other(href!(home).resolve(cx)));
        }
    };
    let url = sign_in.url().to_owned();
    // The callback reaches the listener on 1455, which sends the browser back
    // here (`return_to`) once this task's `finish` has the outcome. A page
    // that arrives first streams it from its live regions.
    let notes = Arc::clone(&app.notes);
    let waiting = app.chatgpt_waiting.clone();
    // Held across the spawn, so the task cannot clear `chatgpt_pending`
    // before it is set.
    let mut held = app.notes();
    let task = tokio::spawn(async move {
        let notice = match sign_in.finish().await {
            Ok(_) => Notice {
                ok: true,
                text: "Signed in to ChatGPT.".into(),
            },
            Err(error) => Notice {
                ok: false,
                // Most of the flow's messages already name ChatGPT.
                text: match error.to_string() {
                    text if text.contains("ChatGPT") => text,
                    text => format!("ChatGPT: {text}"),
                },
            },
        };
        let mut notes = lock(&notes);
        notes.notice = Some(notice);
        notes.chatgpt_pending = None;
        drop(notes);
        waiting.send_replace(false);
    });
    held.chatgpt_pending = Some(Pending {
        url: url.clone(),
        task: task.abort_handle(),
    });
    app.chatgpt_waiting.send_replace(true);
    drop(held);
    Ok(see_other(url))
}

/// Gives up a waiting sign-in, such as one whose tab was closed.
#[route(POST "/chatgpt/cancel")]
async fn chatgpt_cancel(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    let pending = app.notes().chatgpt_pending.take();
    if let Some(pending) = pending {
        pending.task.abort();
        app.done("ChatGPT sign-in canceled.");
    }
    app.chatgpt_waiting.send_replace(false);
    Ok(see_other(href!(home).resolve(cx)))
}

#[route(POST "/chatgpt/sign-out")]
async fn chatgpt_sign_out(cx: &Cx) -> Result<SeeOther> {
    let app = app_context::<App>(cx);
    match app.chatgpt.sign_out().await {
        Ok(()) => app.done("Signed out of ChatGPT."),
        Err(error) => app.failed(format!("ChatGPT: {error}")),
    }
    Ok(see_other(href!(home).resolve(cx)))
}

/// Opens `url` in the default browser, as the `sign-in` example does.
fn open(url: &str) {
    let mut opener = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        // Not `cmd /c start`: cmd would split the URL at its `&`s.
        let mut rundll = std::process::Command::new("rundll32.exe");
        rundll.arg("url.dll,FileProtocolHandler");
        rundll
    } else {
        std::process::Command::new("xdg-open")
    };
    if opener.arg(url).status().is_err() {
        println!("no browser opened; open the page above yourself");
    }
}
