//! A loopback HTTP listener for an OAuth callback, alive only while a
//! sign-in waits. It hands each GET to the flow, which answers once it knows
//! the outcome, so the page can say whether the sign-in worked. Dropping it
//! closes the listener and every connection. That includes the spare ones a
//! browser opens ahead of time, which would otherwise stay attached and could
//! carry a later sign-in's callback to this one (pi's `closeAllConnections`).
use std::net::Ipv4Addr;
use std::time::Duration;

use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::Error;

const MAX_HEAD: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 32;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Loopback {
    port: u16,
    requests: mpsc::Receiver<Request>,
    // The accept loop, which owns every connection's task: dropped, it aborts them all.
    _accept: JoinSet<()>,
}

/// A GET the listener received, waiting for the flow's answer.
pub struct Request {
    url: Url,
    stream: TcpStream,
}

impl Loopback {
    /// Listens on 127.0.0.1:`port`, or on a free port when `port` is 0.
    pub async fn bind(port: u16) -> Result<Self, Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AddrInUse => Error::PortInUse(port),
                _ => Error::Io(e),
            })?;
        let port = listener.local_addr()?.port();
        let (sender, requests) = mpsc::channel(8);
        let mut accept = JoinSet::new();
        accept.spawn(serve(listener, sender));
        Ok(Self {
            port,
            requests,
            _accept: accept,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The next GET, or `None` if the listener stopped.
    pub async fn next(&mut self) -> Option<Request> {
        self.requests.recv().await
    }
}

async fn serve(listener: TcpListener, requests: mpsc::Sender<Request>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) if connections.len() < MAX_CONNECTIONS => {
                    connections.spawn(read(stream, requests.clone()));
                }
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
            Some(_) = connections.join_next() => {}
        }
    }
}

/// Reads one request head. A connection that sends nothing waits here until
/// the listener is dropped.
async fn read(mut stream: TcpStream, requests: mpsc::Sender<Request>) {
    let mut head = Vec::new();
    let mut buffer = [0; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(n) if n > 0 && head.len() + n <= MAX_HEAD => head.extend_from_slice(&buffer[..n]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut line = text.split_whitespace();
    let (method, target) = (line.next().unwrap_or(""), line.next().unwrap_or(""));
    match Url::parse("http://127.0.0.1/").and_then(|base| base.join(target)) {
        // The flow may have finished; then the connection just closes.
        Ok(url) if method == "GET" => drop(requests.send(Request { url, stream }).await),
        _ => {
            respond(
                &mut stream,
                405,
                "Not here",
                "This address only answers a sign-in.",
            )
            .await
        }
    }
}

impl Request {
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The query parameter `name`, if present.
    pub fn param(&self, name: &str) -> Option<String> {
        self.url
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    /// Answers with a small HTML page and closes the connection.
    pub async fn reply(mut self, status: u16, title: &str, detail: &str) {
        respond(&mut self.stream, status, title, detail).await;
    }

    /// Sends the browser on to `location` with a 303 and closes the
    /// connection. `location` is a parsed URL, so it holds no line break.
    pub async fn redirect(mut self, location: &Url) {
        let head = format!(
            "HTTP/1.1 303 See Other\r\nlocation: {location}\r\ncache-control: no-store\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        );
        let write = async {
            self.stream.write_all(head.as_bytes()).await?;
            self.stream.shutdown().await
        };
        let _ = tokio::time::timeout(WRITE_TIMEOUT, write).await;
    }
}

async fn respond(stream: &mut TcpStream, status: u16, title: &str, detail: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Gateway",
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title>\
         <body style=\"font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem\">\
         <h1 style=\"font-size:1.4rem\">{title}</h1><p>{detail}</p></body></html>",
        title = escape(title),
        detail = escape(detail),
    );
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\n\
         cache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let write = async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.shutdown().await
    };
    let _ = tokio::time::timeout(WRITE_TIMEOUT, write).await;
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
