use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use signal_playground::message_relay::MessageRelay;

type SharedRelay = Arc<Mutex<MessageRelay>>;

fn parse_args() -> Result<SocketAddr> {
    let mut args = std::env::args().skip(1);
    let mut listen_addr: Option<SocketAddr> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen-addr" => {
                let raw = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value after --listen-addr"))?;
                let parsed: SocketAddr = raw
                    .parse()
                    .map_err(|e| anyhow!("Invalid --listen-addr '{}': {}", raw, e))?;
                listen_addr = Some(parsed);
            }
            _ => {}
        }
    }

    Ok(listen_addr.unwrap_or_else(|| "127.0.0.1:4000".parse().unwrap()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = parse_args()?;

    let state: SharedRelay = Arc::new(Mutex::new(MessageRelay::new()));

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/message/{recipient}",
            post(publish_message).get(fetch_message),
        )
        .with_state(state);

    println!("[RELAY] Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow!("Could not bind relay listener on {}: {}", addr, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("Message relay server crashed: {}", e))?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn publish_message(
    State(state): State<SharedRelay>,
    Path(recipient): Path<String>,
    body: Bytes,
) -> StatusCode {
    let mut relay = state.lock().unwrap();
    relay.publish_message(&recipient, body.to_vec());
    StatusCode::OK
}

async fn fetch_message(
    State(state): State<SharedRelay>,
    Path(recipient): Path<String>,
) -> Response {
    let mut relay = state.lock().unwrap();

    match relay.fetch_message(&recipient) {
        Some(bytes) => bytes_response(bytes),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn bytes_response(bytes: Vec<u8>) -> Response {
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}
