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

use signal_playground::key_repository::KeyRepository;

type SharedKeyRepository = Arc<Mutex<KeyRepository>>;

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

    Ok(listen_addr.unwrap_or_else(|| "127.0.0.1:3000".parse().unwrap()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = parse_args()?;

    let state: SharedKeyRepository = Arc::new(Mutex::new(KeyRepository::new()));

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/pre-key-bundle/{owner}",
            post(publish_pre_key_bundle).get(fetch_pre_key_bundle),
        )
        .with_state(state);

    println!("[KEY-REPO] Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow!("Could not bind key repository listener on {}: {}", addr, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("Key repository server crashed: {}", e))?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn publish_pre_key_bundle(
    State(state): State<SharedKeyRepository>,
    Path(owner): Path<String>,
    body: Bytes,
) -> Response {
    let mut key_repository = state.lock().unwrap();
    match key_repository.publish_pre_key_bundle(&owner, body.to_vec()) {
        Ok(()) => {
            println!("[KEY-REPO] Stored pre-key bundle for {}", owner);
            StatusCode::OK.into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("invalid pre-key bundle for {}: {}", owner, err),
        )
            .into_response(),
    }
}

async fn fetch_pre_key_bundle(
    State(state): State<SharedKeyRepository>,
    Path(owner): Path<String>,
) -> Response {
    let mut key_repository = state.lock().unwrap();
    match key_repository.fetch_pre_key_bundle(&owner) {
        Ok(Some(outcome)) => {
            println!(
                "[KEY-REPO] Fetched pre-key bundle for {} opk_present={} opk_consumed={} bundle_bytes={}",
                owner,
                outcome.opk_present,
                outcome.opk_consumed,
                outcome.bytes.len()
            );
            bytes_response(outcome.bytes, outcome.opk_present, outcome.opk_consumed)
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not fetch pre-key bundle for {}: {}", owner, err),
        )
            .into_response(),
    }
}

fn bytes_response(bytes: Vec<u8>, opk_present: bool, opk_consumed: bool) -> Response {
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        "x-signal-opk-present",
        HeaderValue::from_static(if opk_present { "true" } else { "false" }),
    );
    response.headers_mut().insert(
        "x-signal-opk-consumed",
        HeaderValue::from_static(if opk_consumed { "true" } else { "false" }),
    );
    response
}
