use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use signal_playground::client::Client;
use signal_playground::worker_api::{handle_command, Command, CommandResponse};

struct WorkerState {
    client: Client,
    key_repository_url: String,
    relay_url: String,
}

type SharedWorkerState = Arc<Mutex<WorkerState>>;

fn parse_args() -> Result<(String, String, String, SocketAddr)> {
    let mut args = std::env::args().skip(1);

    let mut name: Option<String> = None;
    let mut key_repository_url: Option<String> = None;
    let mut relay_url: Option<String> = None;
    let mut listen_addr: Option<SocketAddr> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => {
                name = args.next();
            }
            "--key-repository-url" => {
                key_repository_url = args.next();
            }
            "--relay-url" => {
                relay_url = args.next();
            }
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

    let name = name.ok_or_else(|| anyhow!("Missing --name"))?;
    let key_repository_url =
        key_repository_url.ok_or_else(|| anyhow!("Missing --key-repository-url"))?;
    let relay_url = relay_url.ok_or_else(|| anyhow!("Missing --relay-url"))?;
    let listen_addr = listen_addr.unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap());

    Ok((name, key_repository_url, relay_url, listen_addr))
}

async fn health() -> &'static str {
    "ok"
}

async fn run_command(
    State(state): State<SharedWorkerState>,
    Json(command): Json<Command>,
) -> Json<CommandResponse> {
    let state = state.clone();

    let result = tokio::task::spawn_blocking(move || {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return CommandResponse::error("worker state lock poisoned");
            }
        };

        let key_repository_url = guard.key_repository_url.clone();
        let relay_url = guard.relay_url.clone();

        let WorkerState {
            client,
            key_repository_url: _,
            relay_url: _,
        } = &mut *guard;

        match handle_command(client, &key_repository_url, &relay_url, command) {
            Ok(message) => CommandResponse::ok(message),
            Err(err) => CommandResponse::error(err.to_string()),
        }
    })
    .await;

    match result {
        Ok(response) => Json(response),
        Err(err) => Json(CommandResponse::error(format!(
            "worker task join error: {}",
            err
        ))),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (name, key_repository_url, relay_url, listen_addr) = parse_args()?;

    let state: SharedWorkerState = Arc::new(Mutex::new(WorkerState {
        client: Client::new(&name)?,
        key_repository_url: key_repository_url.clone(),
        relay_url: relay_url.clone(),
    }));

    let app = Router::new()
        .route("/health", get(health))
        .route("/command", post(run_command))
        .with_state(state);

    eprintln!(
        "[WORKER {}] starting on http://{} with KEY_REPOSITORY={} RELAY={}",
        name, listen_addr, key_repository_url, relay_url
    );

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| anyhow!("Could not bind worker listener on {}: {}", listen_addr, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("Worker server crashed: {}", e))?;

    Ok(())
}
