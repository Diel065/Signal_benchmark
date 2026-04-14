use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use signal_playground::key_repository::{GroupInfo, KeyRepository};

type SharedKeyRepository = Arc<Mutex<KeyRepository>>;

#[derive(Debug, Deserialize)]
struct GroupStatePutRequest {
    members: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GroupStateResponse {
    group_id: String,
    current_epoch: u64,
    members: Vec<String>,
}

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
        .route("/group-change/{recipient}", get(fetch_group_change))
        .route(
            "/group-invite/{recipient}",
            post(publish_group_invite).get(fetch_group_invite),
        )
        .route("/group/{group_id}/state/{epoch}", put(put_group_state))
        .route("/group/{group_id}/state", get(get_group_state))
        .route(
            "/group/{group_id}/change/{sender}/{epoch}",
            post(publish_group_change),
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
) -> StatusCode {
    let mut key_repository = state.lock().unwrap();
    key_repository.publish_pre_key_bundle(&owner, body.to_vec());
    println!("[KEY-REPO] Stored pre-key bundle for {}", owner);
    StatusCode::OK
}

async fn fetch_pre_key_bundle(
    State(state): State<SharedKeyRepository>,
    Path(owner): Path<String>,
) -> Response {
    let key_repository = state.lock().unwrap();
    match key_repository.fetch_pre_key_bundle(&owner) {
        Some(bytes) => bytes_response(bytes),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn put_group_state(
    State(state): State<SharedKeyRepository>,
    Path((group_id, epoch)): Path<(String, u64)>,
    Json(body): Json<GroupStatePutRequest>,
) -> Response {
    let mut key_repository = state.lock().unwrap();

    match key_repository.put_group_state(&group_id, epoch, body.members) {
        Ok(()) => {
            println!(
                "[KEY-REPO] Updated group state for group={} epoch={}",
                group_id, epoch
            );
            StatusCode::OK.into_response()
        }
        Err(message) => (StatusCode::CONFLICT, message).into_response(),
    }
}

async fn get_group_state(
    State(state): State<SharedKeyRepository>,
    Path(group_id): Path<String>,
) -> Response {
    let key_repository = state.lock().unwrap();
    match key_repository.get_group_state(&group_id) {
        Some(GroupInfo {
            current_epoch,
            members,
        }) => Json(GroupStateResponse {
            group_id,
            current_epoch,
            members,
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn publish_group_change(
    State(state): State<SharedKeyRepository>,
    Path((group_id, sender, epoch)): Path<(String, String, u64)>,
    body: Bytes,
) -> Response {
    let mut key_repository = state.lock().unwrap();

    match key_repository.publish_group_change(&group_id, &sender, epoch, body.to_vec()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(message) => (StatusCode::CONFLICT, message).into_response(),
    }
}

async fn fetch_group_change(
    State(state): State<SharedKeyRepository>,
    Path(recipient): Path<String>,
) -> Response {
    let mut key_repository = state.lock().unwrap();
    match key_repository.fetch_group_change(&recipient) {
        Some(bytes) => bytes_response(bytes),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn publish_group_invite(
    State(state): State<SharedKeyRepository>,
    Path(recipient): Path<String>,
    body: Bytes,
) -> StatusCode {
    let mut key_repository = state.lock().unwrap();
    key_repository.publish_group_invite(&recipient, body.to_vec());
    println!("[KEY-REPO] Stored encrypted group invite for {}", recipient);
    StatusCode::OK
}

async fn fetch_group_invite(
    State(state): State<SharedKeyRepository>,
    Path(recipient): Path<String>,
) -> Response {
    let mut key_repository = state.lock().unwrap();
    match key_repository.fetch_group_invite(&recipient) {
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
