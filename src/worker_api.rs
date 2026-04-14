use anyhow::{anyhow, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::client::{Client, CommitReceiveOutcome, EpochChangeOutput};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    CreateGroup,
    GeneratePreKeyBundle,
    AddMembers { members: Vec<String> },
    JoinFromGroupInvite,
    SendApplicationMessage { message: String },
    ReceiveApplicationMessage { profile: bool },
    SelfUpdate,
    RemoveMembers { members: Vec<String> },
    ReceiveGroupChange,
    ShowGroupState,
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

#[derive(Debug, Serialize)]
struct GroupStatePutRequest {
    members: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum PendingIntent {
    AddMembers {
        members: Vec<String>,
        new_member_pre_key_bundles: Vec<Vec<u8>>,
        recipient_pre_key_bundles: Vec<(String, Vec<u8>)>,
    },
    RemoveMembers {
        members: Vec<String>,
        recipient_pre_key_bundles: Vec<(String, Vec<u8>)>,
    },
    SelfUpdate {
        recipient_pre_key_bundles: Vec<(String, Vec<u8>)>,
    },
}

pub enum KeyRepositoryPostResult {
    Ok,
    Conflict(String),
}

pub fn key_repo_post_bytes_allow_conflict(
    key_repository_url: &str,
    path: &str,
    bytes: Vec<u8>,
) -> Result<KeyRepositoryPostResult> {
    let url = format!("{key_repository_url}{path}");

    let client = reqwest::blocking::Client::new();
    let response = client.post(url).body(bytes).send()?;

    if response.status().is_success() {
        return Ok(KeyRepositoryPostResult::Ok);
    }

    if response.status() == StatusCode::CONFLICT {
        let body = response.text().unwrap_or_default();
        return Ok(KeyRepositoryPostResult::Conflict(body));
    }

    let status = response.status();
    let body = response.text().unwrap_or_default();
    Err(anyhow!(
        "Key repository POST failed with status {}: {}",
        status,
        body
    ))
}

pub fn key_repo_post_bytes(key_repository_url: &str, path: &str, bytes: Vec<u8>) -> Result<()> {
    match key_repo_post_bytes_allow_conflict(key_repository_url, path, bytes)? {
        KeyRepositoryPostResult::Ok => Ok(()),
        KeyRepositoryPostResult::Conflict(message) => {
            Err(anyhow!("Unexpected key repository conflict: {}", message))
        }
    }
}

pub fn key_repo_put_json<T: Serialize>(
    key_repository_url: &str,
    path: &str,
    body: &T,
) -> Result<()> {
    let url = format!("{key_repository_url}{path}");

    let client = reqwest::blocking::Client::new();
    let response = client.put(url).json(body).send()?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "Key repository PUT failed with status {}: {}",
            status,
            body
        ));
    }

    Ok(())
}

pub fn key_repo_get_bytes(key_repository_url: &str, path: &str) -> Result<Vec<u8>> {
    let url = format!("{key_repository_url}{path}");

    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Key repository GET failed with status {}",
            response.status()
        ));
    }

    Ok(response.bytes()?.to_vec())
}

pub fn relay_post_application_message(
    relay_url: &str,
    group_id: &str,
    sender: &str,
    recipients: &[String],
    bytes: Vec<u8>,
) -> Result<()> {
    let url = format!(
        "{}/group/{}/application-message/{}",
        relay_url.trim_end_matches('/'),
        group_id,
        sender
    );

    let recipients_header = recipients.join(",");

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(url)
        .header("x-recipients", recipients_header)
        .body(bytes)
        .send()?;

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

pub fn relay_get_application_message(relay_url: &str, recipient: &str) -> Result<Vec<u8>> {
    let url = format!(
        "{}/application-message/{}",
        relay_url.trim_end_matches('/'),
        recipient
    );

    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Relay GET failed with status {}",
            response.status()
        ));
    }

    Ok(response.bytes()?.to_vec())
}

pub fn update_key_repository_group_state(client: &Client, key_repository_url: &str) -> Result<()> {
    let group_id = client.group_id_hex()?;
    let epoch = client.current_epoch_u64()?;
    let members = client.member_names()?;

    let path = format!("/group/{group_id}/state/{epoch}");
    let body = GroupStatePutRequest { members };

    key_repo_put_json(key_repository_url, &path, &body)
}

pub fn publish_epoch_change(
    client: &mut Client,
    key_repository_url: &str,
    result: EpochChangeOutput,
) -> Result<KeyRepositoryPostResult> {
    let group_id = client.group_id_hex()?;
    let epoch = client.current_epoch_u64()?;
    let path = format!("/group/{group_id}/change/{}/{epoch}", client.name);

    key_repo_post_bytes_allow_conflict(key_repository_url, &path, result.commit_bytes)
}

pub fn try_start_intent(
    client: &mut Client,
    key_repository_url: &str,
    intent: &PendingIntent,
) -> Result<KeyRepositoryPostResult> {
    let result = match intent {
        PendingIntent::AddMembers {
            members,
            new_member_pre_key_bundles,
            recipient_pre_key_bundles,
        } => client.add_members(
            new_member_pre_key_bundles,
            members,
            recipient_pre_key_bundles,
        )?,
        PendingIntent::RemoveMembers {
            members,
            recipient_pre_key_bundles,
        } => client.remove_members(members, recipient_pre_key_bundles)?,
        PendingIntent::SelfUpdate {
            recipient_pre_key_bundles,
        } => client.self_update(recipient_pre_key_bundles)?,
    };

    match publish_epoch_change(client, key_repository_url, result)? {
        KeyRepositoryPostResult::Ok => Ok(KeyRepositoryPostResult::Ok),
        KeyRepositoryPostResult::Conflict(message) => {
            client.rollback_pending_commit()?;
            Ok(KeyRepositoryPostResult::Conflict(message))
        }
    }
}

pub fn maybe_retry_pending_intent(
    client: &mut Client,
    key_repository_url: &str,
    queued_intent: &mut Option<PendingIntent>,
) -> Result<Option<String>> {
    let Some(intent) = queued_intent.clone() else {
        return Ok(None);
    };

    match try_start_intent(client, key_repository_url, &intent)? {
        KeyRepositoryPostResult::Ok => {
            *queued_intent = None;

            let text = match intent {
                PendingIntent::AddMembers { members, .. } => {
                    format!(
                        "queued add_members for {:?} was retried and published",
                        members
                    )
                }
                PendingIntent::RemoveMembers { members, .. } => {
                    format!(
                        "queued remove_members for {:?} was retried and published",
                        members
                    )
                }
                PendingIntent::SelfUpdate { .. } => {
                    "queued self_update was retried and published".to_string()
                }
            };

            Ok(Some(text))
        }
        KeyRepositoryPostResult::Conflict(message) => {
            *queued_intent = Some(intent);
            Ok(Some(format!(
                "queued intent retry still conflicted and remains queued: {}",
                message
            )))
        }
    }
}

pub fn handle_command(
    client: &mut Client,
    key_repository_url: &str,
    relay_url: &str,
    queued_intent: &mut Option<PendingIntent>,
    command: Command,
) -> Result<String> {
    match command {
        Command::CreateGroup => {
            client.create_group()?;
            update_key_repository_group_state(client, key_repository_url)?;
            Ok("Signal group created and key repository group state registered".to_string())
        }

        Command::GeneratePreKeyBundle => {
            let pre_key_bundle_bytes = client.generate_pre_key_bundle()?;
            let path = format!("/pre-key-bundle/{}", client.name);
            key_repo_post_bytes(key_repository_url, &path, pre_key_bundle_bytes)?;
            Ok(format!("pre-key bundle uploaded for {}", client.name))
        }

        Command::AddMembers { members } => {
            let mut new_member_pre_key_bundles = Vec::with_capacity(members.len());
            for member in &members {
                let path = format!("/pre-key-bundle/{member}");
                new_member_pre_key_bundles.push(key_repo_get_bytes(key_repository_url, &path)?);
            }

            let existing_recipients: Vec<String> = client
                .member_names()?
                .into_iter()
                .filter(|member| member != &client.name)
                .collect();
            let recipient_pre_key_bundles =
                fetch_pre_key_bundles(key_repository_url, &existing_recipients)?;

            let intent = PendingIntent::AddMembers {
                members: members.clone(),
                new_member_pre_key_bundles,
                recipient_pre_key_bundles,
            };

            match try_start_intent(client, key_repository_url, &intent)? {
                KeyRepositoryPostResult::Ok => Ok(format!(
                    "Signal members {:?} added locally with pairwise group-control messages; change published, waiting for key repository echo",
                    members
                )),
                KeyRepositoryPostResult::Conflict(message) => {
                    *queued_intent = Some(intent);
                    Ok(format!(
                        "add_members for {:?} lost the epoch race and was queued for retry: {}",
                        members, message
                    ))
                }
            }
        }

        Command::JoinFromGroupInvite => {
            let invite_path = format!("/group-invite/{}", client.name);
            let invite_bytes = key_repo_get_bytes(key_repository_url, &invite_path)?;

            client.join_from_group_invite(&invite_bytes)?;

            Ok(format!("{} joined from Signal group invite", client.name))
        }

        Command::SendApplicationMessage { message } => {
            let sender = client.name.clone();
            let mut recipients = client.member_names()?;
            recipients.retain(|recipient| recipient != &sender);

            let recipient_pre_key_bundles = fetch_pre_key_bundles(key_repository_url, &recipients)?;
            let message_bytes =
                client.send_application_message(message.as_bytes(), &recipient_pre_key_bundles)?;
            let group_id = client.group_id_hex()?;

            relay_post_application_message(
                relay_url,
                &group_id,
                &sender,
                &recipients,
                message_bytes,
            )?;

            Ok("pairwise Signal application message broadcast to group".to_string())
        }

        Command::ReceiveApplicationMessage { profile } => {
            let message_bytes = relay_get_application_message(relay_url, &client.name)?;
            let plaintext = client.receive_application_message(&message_bytes, profile)?;
            let text = String::from_utf8_lossy(&plaintext).to_string();
            Ok(format!("application message received: {}", text))
        }

        Command::SelfUpdate => {
            let recipients: Vec<String> = client
                .member_names()?
                .into_iter()
                .filter(|member| member != &client.name)
                .collect();
            let recipient_pre_key_bundles = fetch_pre_key_bundles(key_repository_url, &recipients)?;
            let intent = PendingIntent::SelfUpdate {
                recipient_pre_key_bundles,
            };

            match try_start_intent(client, key_repository_url, &intent)? {
                KeyRepositoryPostResult::Ok => Ok(
                    "self_update pairwise Signal group-control change published to group"
                        .to_string(),
                ),
                KeyRepositoryPostResult::Conflict(message) => {
                    *queued_intent = Some(intent);
                    Ok(format!(
                        "self_update lost the epoch race and was queued for retry: {}",
                        message
                    ))
                }
            }
        }

        Command::RemoveMembers { members } => {
            let recipients: Vec<String> = client
                .member_names()?
                .into_iter()
                .filter(|member| member != &client.name && !members.contains(member))
                .collect();
            let recipient_pre_key_bundles = fetch_pre_key_bundles(key_repository_url, &recipients)?;

            let intent = PendingIntent::RemoveMembers {
                members: members.clone(),
                recipient_pre_key_bundles,
            };

            match try_start_intent(client, key_repository_url, &intent)? {
                KeyRepositoryPostResult::Ok => Ok(format!(
                    "Signal members {:?} removed locally; pairwise group-control change published",
                    members
                )),
                KeyRepositoryPostResult::Conflict(message) => {
                    *queued_intent = Some(intent);
                    Ok(format!(
                        "remove_members for {:?} lost the epoch race and was queued for retry: {}",
                        members, message
                    ))
                }
            }
        }

        Command::ReceiveGroupChange => {
            let path = format!("/group-change/{}", client.name);
            let change_bytes = key_repo_get_bytes(key_repository_url, &path)?;

            match client.receive_commit(&change_bytes)? {
                CommitReceiveOutcome::ExternalChangeApplied { self_removed } => {
                    if self_removed {
                        *queued_intent = None;
                        Ok("external Signal group change received; this client was removed and local group state was cleared".to_string())
                    } else {
                        update_key_repository_group_state(client, key_repository_url)?;

                        let retry_message =
                            maybe_retry_pending_intent(client, key_repository_url, queued_intent)?;

                        match retry_message {
                            Some(text) => Ok(format!(
                                "external Signal group change received and processed; key repository group state updated; {}",
                                text
                            )),
                            None => Ok(
                                "external Signal group change received and processed; key repository group state updated"
                                    .to_string(),
                            ),
                        }
                    }
                }

                CommitReceiveOutcome::OwnChangeAccepted {
                    self_removed,
                    group_invites,
                } => {
                    if self_removed {
                        *queued_intent = None;
                        Ok("own Signal group change accepted from key repository; this client was removed and local group state was cleared".to_string())
                    } else {
                        for (recipient, invite) in group_invites {
                            let invite_path = format!("/group-invite/{recipient}");
                            key_repo_post_bytes(key_repository_url, &invite_path, invite)?;
                        }

                        update_key_repository_group_state(client, key_repository_url)?;
                        Ok("own Signal group change accepted from key repository; local state updated and encrypted group invites published"
                            .to_string())
                    }
                }
            }
        }

        Command::ShowGroupState => {
            let group_id = client.group_id_hex()?;
            let epoch = client.current_epoch_u64()?;
            let members = client.member_names()?;

            Ok(format!(
                "group_id={}, epoch={}, members={:?}",
                group_id, epoch, members
            ))
        }
    }
}

fn fetch_pre_key_bundles(
    key_repository_url: &str,
    members: &[String],
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut bundles = Vec::with_capacity(members.len());
    for member in members {
        let path = format!("/pre-key-bundle/{member}");
        bundles.push((
            member.clone(),
            key_repo_get_bytes(key_repository_url, &path)?,
        ));
    }
    Ok(bundles)
}
