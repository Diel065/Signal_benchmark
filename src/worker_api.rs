use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::{
    client::Client,
    profiling::{finish_and_emit, ProfileScope},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    GeneratePreKeyBundle,
    SendFanoutMessage {
        recipients: Vec<String>,
        message: String,
    },
    ReceivePairwiseMessage {
        profile: bool,
    },
    SessionExists {
        peer: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub status: String,
    pub message: String,
}

impl CommandResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            status: "ok".to_string(),
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            message: message.into(),
        }
    }
}

pub fn key_repo_post_bytes(key_repository_url: &str, path: &str, bytes: Vec<u8>) -> Result<()> {
    let url = format!("{key_repository_url}{path}");

    let client = reqwest::blocking::Client::new();
    let response = client.post(url).body(bytes).send()?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "Key repository POST failed with status {}: {}",
            status,
            body
        ));
    }

    Ok(())
}

pub fn key_repo_get_bytes(key_repository_url: &str, path: &str) -> Result<Vec<u8>> {
    let fetched = key_repo_get_pre_key_bundle(key_repository_url, path)?;
    Ok(fetched.bytes)
}

struct FetchedPreKeyBundle {
    bytes: Vec<u8>,
    opk_present: bool,
    opk_consumed: bool,
}

fn parse_bool_header(response: &reqwest::blocking::Response, header_name: &str) -> Result<bool> {
    let raw = response
        .headers()
        .get(header_name)
        .ok_or_else(|| anyhow!("Missing response header {}", header_name))?;
    let raw = raw
        .to_str()
        .map_err(|err| anyhow!("Invalid response header {}: {}", header_name, err))?;
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(anyhow!(
            "Unexpected response header {} value {}",
            header_name,
            other
        )),
    }
}

fn key_repo_get_pre_key_bundle(
    key_repository_url: &str,
    path: &str,
) -> Result<FetchedPreKeyBundle> {
    let url = format!("{key_repository_url}{path}");

    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Key repository GET failed with status {}",
            response.status()
        ));
    }

    Ok(FetchedPreKeyBundle {
        opk_present: parse_bool_header(&response, "x-signal-opk-present")?,
        opk_consumed: parse_bool_header(&response, "x-signal-opk-consumed")?,
        bytes: response.bytes()?.to_vec(),
    })
}

pub fn relay_post_message(relay_url: &str, recipient: &str, bytes: Vec<u8>) -> Result<()> {
    let url = format!("{}/message/{}", relay_url.trim_end_matches('/'), recipient);

    let client = reqwest::blocking::Client::new();
    let response = client.post(url).body(bytes).send()?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "Relay POST failed with status {}: {}",
            status,
            body
        ));
    }

    Ok(())
}

pub fn relay_get_message(relay_url: &str, recipient: &str) -> Result<Vec<u8>> {
    let url = format!("{}/message/{}", relay_url.trim_end_matches('/'), recipient);

    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Relay GET failed with status {}",
            response.status()
        ));
    }

    Ok(response.bytes()?.to_vec())
}

fn fetch_missing_pre_key_bundles(
    client: &Client,
    key_repository_url: &str,
    peers: &[String],
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut bundles = Vec::new();
    for peer in peers {
        if client.session_exists(peer)? {
            continue;
        }
        let path = format!("/pre-key-bundle/{peer}");
        let scope = ProfileScope::start("fetch_prekey_bundle", "key-repository-http");
        let fetched = key_repo_get_pre_key_bundle(key_repository_url, &path)?;
        let fetched_bytes = fetched.bytes.len();
        finish_and_emit(scope, |event| {
            event.protocol_bytes = Some(fetched_bytes);
            event.wire_bytes = Some(fetched_bytes);
            event.harness_metadata_bytes = Some(0);
            event.ciphertext_count = Some(0);
            event.recipient_count = Some(1);
            event.fanout_recipients = Some(1);
            event.session_setup_count = Some(0);
            event.payload_class = Some("prekey_bundle_fetch".to_string());
            event.pre_key_bundle_fetch_bytes = Some(fetched_bytes);
            event.opk_present_count = Some(usize::from(fetched.opk_present));
            event.opk_consumed_count = Some(usize::from(fetched.opk_consumed));
        });
        bundles.push((peer.clone(), fetched.bytes));
    }
    Ok(bundles)
}

pub fn handle_command(
    client: &mut Client,
    key_repository_url: &str,
    relay_url: &str,
    command: Command,
) -> Result<String> {
    match command {
        Command::GeneratePreKeyBundle => {
            let pre_key_bundle_bytes = client.generate_pre_key_bundle()?;
            let path = format!("/pre-key-bundle/{}", client.name);
            key_repo_post_bytes(key_repository_url, &path, pre_key_bundle_bytes)?;
            Ok(format!("pre-key bundle uploaded for {}", client.name))
        }

        Command::SendFanoutMessage {
            recipients,
            message,
        } => {
            if recipients.is_empty() {
                return Err(anyhow!("SendFanoutMessage requires at least one recipient"));
            }

            let recipient_pre_key_bundles =
                fetch_missing_pre_key_bundles(client, key_repository_url, &recipients)?;
            let messages = client.send_application_message(
                message.as_bytes(),
                &recipients,
                &recipient_pre_key_bundles,
            )?;

            for (recipient, message_bytes) in messages {
                relay_post_message(relay_url, &recipient, message_bytes)?;
            }

            Ok(format!(
                "fanout message sent to {} recipients",
                recipients.len()
            ))
        }

        Command::ReceivePairwiseMessage { profile } => {
            let message_bytes = relay_get_message(relay_url, &client.name)?;
            let plaintext = client.receive_application_message(&message_bytes, profile)?;
            let text = String::from_utf8_lossy(&plaintext).to_string();
            Ok(format!("pairwise message received: {}", text))
        }

        Command::SessionExists { peer } => Ok(format!(
            "session_exists peer={} value={}",
            peer,
            client.session_exists(&peer)?
        )),
    }
}
