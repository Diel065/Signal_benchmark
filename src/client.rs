use std::collections::{HashMap, HashSet};

use allocation_counter::measure;
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use libsignal_core::curve::{KeyPair, PrivateKey, PublicKey};
use rand::{Rng, TryRngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_crypto::{aes_256_cbc_decrypt, aes_256_cbc_encrypt, CryptographicMac};
use uuid::Uuid;

use crate::{
    debug::print_bytes,
    profiling::{finish_and_emit, ProfileScope},
};

const X3DH_LABEL: &[u8] = b"signal_playground_x3dh_v1";
const X3DH_CHAIN_LABEL: &[u8] = b"signal_playground_x3dh_chain_v1";
const X3DH_MESSAGE_TYPE: u8 = 1;
const SIGNAL_CIPHERSUITE_LABEL: &str = "Signal X3DH + pairwise symmetric ratchet";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionProtocol {
    X3dh,
}

impl SessionProtocol {
    fn label(self) -> &'static str {
        match self {
            SessionProtocol::X3dh => SIGNAL_CIPHERSUITE_LABEL,
        }
    }
}

#[derive(Clone, Debug)]
struct GroupState {
    group_id: String,
    epoch: u64,
    members: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EpochChangeOutput {
    pub commit_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum CommitReceiveOutcome {
    OwnChangeAccepted {
        self_removed: bool,
        group_invites: Vec<(String, Vec<u8>)>,
    },
    ExternalChangeApplied {
        self_removed: bool,
    },
}

#[derive(Clone)]
struct LocalPreKey {
    key_pair: KeyPair,
}

#[derive(Clone)]
struct PairwiseSession {
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WirePreKeyBundle {
    protocol: String,
    owner: String,
    registration_id: u32,
    device_id: u8,
    pre_key_id: Option<u32>,
    pre_key_public: Option<Vec<u8>>,
    signed_pre_key_id: u32,
    signed_pre_key_public: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    identity_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct X3dhHeader {
    identity_key: Vec<u8>,
    base_key: Vec<u8>,
    signed_pre_key_id: u32,
    pre_key_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct X3dhCiphertext {
    header: Option<X3dhHeader>,
    counter: u64,
    ciphertext: Vec<u8>,
    mac: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairwiseCiphertext {
    recipient: String,
    message_type: u8,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GroupControlPlaintext {
    op: String,
    group_id: String,
    from_epoch: u64,
    to_epoch: u64,
    sender: String,
    members_after: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GroupChangeEnvelope {
    op: String,
    group_id: String,
    from_epoch: u64,
    to_epoch: u64,
    sender: String,
    members_after: Vec<String>,
    ciphertexts: Vec<PairwiseCiphertext>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GroupInvitePlaintext {
    group_id: String,
    epoch: u64,
    inviter: String,
    members: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GroupInviteEnvelope {
    inviter: String,
    message_type: u8,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GroupApplicationEnvelope {
    group_id: String,
    epoch: u64,
    sender: String,
    ciphertexts: Vec<PairwiseCiphertext>,
}

pub struct Client {
    pub name: String,
    session_protocol: SessionProtocol,
    identity_key_pair: KeyPair,
    registration_id: u32,
    signed_pre_keys: HashMap<u32, LocalPreKey>,
    one_time_pre_keys: HashMap<u32, LocalPreKey>,
    pairwise_sessions: HashMap<String, PairwiseSession>,
    group: Option<GroupState>,
    known_sessions: HashSet<String>,
    pending_commit_bytes: Option<Vec<u8>>,
    pending_group_after: Option<GroupState>,
    pending_group_invites: Vec<(String, Vec<u8>)>,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
}

impl Client {
    fn fresh(name: &str) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity_key_pair = KeyPair::generate(&mut rng);
        let registration_id = (rng.random::<u32>() & 0x3fff).max(1);
        let public_key = identity_key_pair.public_key.serialize();

        print_bytes(&format!("{} Signal identity public key", name), &public_key);
        print_bytes(&format!("{} Signal address bytes", name), name.as_bytes());

        Ok(Self {
            name: name.to_string(),
            session_protocol: SessionProtocol::X3dh,
            identity_key_pair,
            registration_id,
            signed_pre_keys: HashMap::new(),
            one_time_pre_keys: HashMap::new(),
            pairwise_sessions: HashMap::new(),
            group: None,
            known_sessions: HashSet::new(),
            pending_commit_bytes: None,
            pending_group_after: None,
            pending_group_invites: Vec::new(),
            next_pre_key_id: 1,
            next_signed_pre_key_id: 1,
        })
    }

    pub fn new(name: &str) -> Result<Self> {
        Self::fresh(name)
    }

    fn reset_local_state_fully(&mut self) -> Result<()> {
        let name = self.name.clone();
        *self = Self::fresh(&name)?;
        Ok(())
    }

    fn random_group_id() -> String {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        Uuid::from_u128(rng.random()).to_string()
    }

    pub fn group_id_hex(&self) -> Result<String> {
        Ok(self
            .group
            .as_ref()
            .ok_or_else(|| anyhow!("Client is not in a Signal group"))?
            .group_id
            .clone())
    }

    pub fn current_epoch_u64(&self) -> Result<u64> {
        Ok(self
            .group
            .as_ref()
            .ok_or_else(|| anyhow!("Client is not in a Signal group"))?
            .epoch)
    }

    pub fn member_names(&self) -> Result<Vec<String>> {
        Ok(self
            .group
            .as_ref()
            .ok_or_else(|| anyhow!("Client is not in a Signal group"))?
            .members
            .clone())
    }

    pub fn create_group(&mut self) -> Result<()> {
        self.group = Some(GroupState {
            group_id: Self::random_group_id(),
            epoch: 0,
            members: vec![self.name.clone()],
        });

        if let Some(group) = &self.group {
            println!(
                "[DBG] {} Signal group_id={} epoch={}",
                self.name, group.group_id, group.epoch
            );
        }

        Ok(())
    }

    pub fn generate_pre_key_bundle(&mut self) -> Result<Vec<u8>> {
        let scope = ProfileScope::start("pre_key_bundle_create", "libsignal-x3dh");

        let mut measured_result: Option<Result<Vec<u8>>> = None;
        let allocation_info = measure(|| {
            measured_result = Some(self.generate_pre_key_bundle_inner());
        });

        let bytes = measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to generate Signal X3DH pre-key bundle")?;

        finish_and_emit(scope, |event| {
            event.artifact_size_bytes = Some(bytes.len());
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.ciphersuite = Some(self.session_protocol.label().to_string());
        });

        print_bytes(&format!("{} Signal X3DH pre-key bundle", self.name), &bytes);
        Ok(bytes)
    }

    fn generate_pre_key_bundle_inner(&mut self) -> Result<Vec<u8>> {
        let mut rng = rand::rngs::OsRng.unwrap_err();

        let pre_key_id = self.next_pre_key_id;
        self.next_pre_key_id = self.next_pre_key_id.saturating_add(1);

        let signed_pre_key_id = self.next_signed_pre_key_id;
        self.next_signed_pre_key_id = self.next_signed_pre_key_id.saturating_add(1);

        let one_time_pre_key_pair = KeyPair::generate(&mut rng);
        let signed_pre_key_pair = KeyPair::generate(&mut rng);
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = self
            .identity_key_pair
            .private_key
            .calculate_signature(&signed_pre_key_public, &mut rng)?;

        self.one_time_pre_keys.insert(
            pre_key_id,
            LocalPreKey {
                key_pair: one_time_pre_key_pair,
            },
        );
        self.signed_pre_keys.insert(
            signed_pre_key_id,
            LocalPreKey {
                key_pair: signed_pre_key_pair,
            },
        );

        let wire = WirePreKeyBundle {
            protocol: "x3dh".to_string(),
            owner: self.name.clone(),
            registration_id: self.registration_id,
            device_id: 1,
            pre_key_id: Some(pre_key_id),
            pre_key_public: Some(one_time_pre_key_pair.public_key.serialize().to_vec()),
            signed_pre_key_id,
            signed_pre_key_public: signed_pre_key_public.to_vec(),
            signed_pre_key_signature: signed_pre_key_signature.to_vec(),
            identity_key: self.identity_key_pair.public_key.serialize().to_vec(),
        };

        Ok(bincode::serialize(&wire)?)
    }

    fn clear_pending_local_state(&mut self) {
        self.pending_commit_bytes = None;
        self.pending_group_after = None;
        self.pending_group_invites.clear();
    }

    fn bundle_map(pre_key_bundles: &[(String, Vec<u8>)]) -> HashMap<String, Vec<u8>> {
        pre_key_bundles.iter().cloned().collect()
    }

    fn create_session_from_bundle(
        &mut self,
        remote_name: &str,
        pre_key_bundle_bytes: &[u8],
    ) -> Result<X3dhHeader> {
        let bundle = decode_pre_key_bundle(pre_key_bundle_bytes)?;
        if bundle.owner != remote_name {
            return Err(anyhow!(
                "Pre-key bundle owner mismatch: expected {}, got {}",
                remote_name,
                bundle.owner
            ));
        }

        let their_identity = PublicKey::deserialize(&bundle.identity_key)?;
        let their_signed_pre_key = PublicKey::deserialize(&bundle.signed_pre_key_public)?;
        if !their_identity.verify_signature(
            &their_signed_pre_key.serialize(),
            &bundle.signed_pre_key_signature,
        ) {
            return Err(anyhow!(
                "Invalid signed pre-key signature for Signal peer {}",
                remote_name
            ));
        }

        let their_one_time_pre_key = match &bundle.pre_key_public {
            Some(bytes) => Some(PublicKey::deserialize(bytes)?),
            None => None,
        };

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let base_key_pair = KeyPair::generate(&mut rng);

        let root_key = derive_x3dh_initiator_root_key(
            &self.identity_key_pair,
            &base_key_pair,
            &their_identity,
            &their_signed_pre_key,
            their_one_time_pre_key.as_ref(),
        )?;

        self.pairwise_sessions.insert(
            remote_name.to_string(),
            PairwiseSession::new(&root_key, &self.name, remote_name),
        );
        self.known_sessions.insert(remote_name.to_string());

        Ok(X3dhHeader {
            identity_key: self.identity_key_pair.public_key.serialize().to_vec(),
            base_key: base_key_pair.public_key.serialize().to_vec(),
            signed_pre_key_id: bundle.signed_pre_key_id,
            pre_key_id: bundle.pre_key_id,
        })
    }

    fn create_session_from_header(&mut self, remote_name: &str, header: &X3dhHeader) -> Result<()> {
        let their_identity = PublicKey::deserialize(&header.identity_key)?;
        let their_base_key = PublicKey::deserialize(&header.base_key)?;

        let signed_pre_key = self
            .signed_pre_keys
            .get(&header.signed_pre_key_id)
            .ok_or_else(|| {
                anyhow!(
                    "Missing local signed pre-key {} for Signal peer {}",
                    header.signed_pre_key_id,
                    remote_name
                )
            })?;

        let one_time_pre_key = match header.pre_key_id {
            Some(id) => Some(
                self.one_time_pre_keys
                    .get(&id)
                    .ok_or_else(|| {
                        anyhow!(
                            "Missing local one-time pre-key {} for Signal peer {}",
                            id,
                            remote_name
                        )
                    })?
                    .key_pair,
            ),
            None => None,
        };

        let root_key = derive_x3dh_responder_root_key(
            &self.identity_key_pair,
            &signed_pre_key.key_pair,
            one_time_pre_key.as_ref(),
            &their_identity,
            &their_base_key,
        )?;

        self.pairwise_sessions.insert(
            remote_name.to_string(),
            PairwiseSession::new(&root_key, &self.name, remote_name),
        );
        self.known_sessions.insert(remote_name.to_string());
        Ok(())
    }

    fn encrypt_for_recipient(
        &mut self,
        recipient: &str,
        plaintext: &[u8],
        pre_key_bundle_bytes: Option<&[u8]>,
    ) -> Result<PairwiseCiphertext> {
        let header = if self.pairwise_sessions.contains_key(recipient) {
            None
        } else {
            Some(self.create_session_from_bundle(
                recipient,
                pre_key_bundle_bytes.ok_or_else(|| {
                    anyhow!("Missing pre-key bundle for Signal peer '{}'", recipient)
                })?,
            )?)
        };

        let session = self
            .pairwise_sessions
            .get_mut(recipient)
            .ok_or_else(|| anyhow!("Missing Signal pairwise session for {}", recipient))?;
        let counter = session.send_counter;
        let keys = session.next_send_message_keys();
        let ciphertext = aes_256_cbc_encrypt(plaintext, &keys.cipher_key, &keys.iv)
            .map_err(|err| anyhow!("Signal X3DH encryption failed: {}", err))?;
        let mac = hmac_sha256(&keys.mac_key, &ciphertext)?;

        let wire = X3dhCiphertext {
            header,
            counter,
            ciphertext,
            mac,
        };

        Ok(PairwiseCiphertext {
            recipient: recipient.to_string(),
            message_type: X3DH_MESSAGE_TYPE,
            ciphertext: bincode::serialize(&wire)?,
        })
    }

    fn decrypt_from_sender(
        &mut self,
        sender: &str,
        message_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if message_type != X3DH_MESSAGE_TYPE {
            return Err(anyhow!("Unsupported Signal message type {}", message_type));
        }

        let wire: X3dhCiphertext =
            bincode::deserialize(ciphertext).context("Could not deserialize X3DH ciphertext")?;

        if !self.pairwise_sessions.contains_key(sender) {
            let header = wire
                .header
                .as_ref()
                .ok_or_else(|| anyhow!("Missing X3DH header for new Signal peer {}", sender))?;
            self.create_session_from_header(sender, header)?;
        }

        let session = self
            .pairwise_sessions
            .get_mut(sender)
            .ok_or_else(|| anyhow!("Missing Signal pairwise session for {}", sender))?;
        if wire.counter != session.recv_counter {
            return Err(anyhow!(
                "Unexpected Signal message counter from {}: expected {}, got {}",
                sender,
                session.recv_counter,
                wire.counter
            ));
        }

        let keys = session.next_recv_message_keys();
        let expected_mac = hmac_sha256(&keys.mac_key, &wire.ciphertext)?;
        if expected_mac != wire.mac {
            return Err(anyhow!("Signal X3DH message MAC verification failed"));
        }

        let plaintext = aes_256_cbc_decrypt(&wire.ciphertext, &keys.cipher_key, &keys.iv)
            .map_err(|err| anyhow!("Signal X3DH decryption failed: {}", err))?;
        self.known_sessions.insert(sender.to_string());
        Ok(plaintext)
    }

    fn group_ref(&self) -> Result<&GroupState> {
        self.group
            .as_ref()
            .ok_or_else(|| anyhow!("Client is not in a Signal group"))
    }

    fn build_group_change(
        &mut self,
        op: &str,
        members_after: Vec<String>,
        invitee_names: &[String],
        pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<EpochChangeOutput> {
        let before = self.group_ref()?.clone();
        let from_epoch = before.epoch;
        let to_epoch = from_epoch + 1;
        let bundle_map = Self::bundle_map(pre_key_bundles);

        let control_recipients: Vec<String> = before
            .members
            .iter()
            .filter(|member| *member != &self.name && members_after.contains(member))
            .cloned()
            .collect();

        let scope = ProfileScope::start(format!("{op}_commit_create"), "libsignal-x3dh");
        let member_count_before = before.members.len();
        let invitee_count = invitee_names.len();

        let mut measured_result: Option<Result<(Vec<u8>, Vec<(String, Vec<u8>)>, GroupState)>> =
            None;

        let allocation_info = measure(|| {
            measured_result = Some((|| {
                let control = GroupControlPlaintext {
                    op: op.to_string(),
                    group_id: before.group_id.clone(),
                    from_epoch,
                    to_epoch,
                    sender: self.name.clone(),
                    members_after: members_after.clone(),
                };
                let control_bytes = bincode::serialize(&control)?;

                let mut ciphertexts = Vec::with_capacity(control_recipients.len());
                for recipient in &control_recipients {
                    ciphertexts.push(self.encrypt_for_recipient(
                        recipient,
                        &control_bytes,
                        bundle_map.get(recipient).map(Vec::as_slice),
                    )?);
                }

                let change = GroupChangeEnvelope {
                    op: op.to_string(),
                    group_id: before.group_id.clone(),
                    from_epoch,
                    to_epoch,
                    sender: self.name.clone(),
                    members_after: members_after.clone(),
                    ciphertexts,
                };
                let change_bytes = bincode::serialize(&change)?;

                let invite_plaintext = GroupInvitePlaintext {
                    group_id: before.group_id.clone(),
                    epoch: to_epoch,
                    inviter: self.name.clone(),
                    members: members_after.clone(),
                };
                let invite_plaintext_bytes = bincode::serialize(&invite_plaintext)?;

                let mut group_invites = Vec::with_capacity(invitee_names.len());
                for invitee in invitee_names {
                    let encrypted = self.encrypt_for_recipient(
                        invitee,
                        &invite_plaintext_bytes,
                        bundle_map.get(invitee).map(Vec::as_slice),
                    )?;
                    let invite = GroupInviteEnvelope {
                        inviter: self.name.clone(),
                        message_type: encrypted.message_type,
                        ciphertext: encrypted.ciphertext,
                    };
                    group_invites.push((invitee.clone(), bincode::serialize(&invite)?));
                }

                let group_after = GroupState {
                    group_id: before.group_id.clone(),
                    epoch: to_epoch,
                    members: members_after,
                };

                Ok::<_, anyhow::Error>((change_bytes, group_invites, group_after))
            })());
        });

        let (change_bytes, group_invites, group_after) = measured_result
            .expect("allocation_counter measure closure did not run")
            .with_context(|| format!("Failed to create Signal {op} group change"))?;

        let invite_bytes_total: usize = group_invites.iter().map(|(_, bytes)| bytes.len()).sum();
        let artifact_size_bytes = change_bytes.len() + invite_bytes_total;

        finish_and_emit(scope, |event| {
            event.group_epoch = Some(from_epoch);
            event.member_count = Some(member_count_before);
            event.invitee_count = Some(invitee_count);
            event.artifact_size_bytes = Some(artifact_size_bytes);
            event.encrypted_secrets_count = Some(
                group_after
                    .members
                    .iter()
                    .filter(|member| *member != &self.name)
                    .count(),
            );
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.ciphersuite = Some(self.session_protocol.label().to_string());
        });

        print_bytes(&format!("{} Signal group change", self.name), &change_bytes);

        self.pending_commit_bytes = Some(change_bytes.clone());
        self.pending_group_after = Some(group_after);
        self.pending_group_invites = group_invites;

        Ok(EpochChangeOutput {
            commit_bytes: change_bytes,
        })
    }

    pub fn add_members(
        &mut self,
        pre_key_bundle_bytes_list: &[Vec<u8>],
        member_names: &[String],
        recipient_pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<EpochChangeOutput> {
        if pre_key_bundle_bytes_list.len() != member_names.len() {
            return Err(anyhow!(
                "Number of pre-key bundles does not match number of Signal member names"
            ));
        }

        let mut all_bundles = recipient_pre_key_bundles.to_vec();
        for (member, bytes) in member_names.iter().zip(pre_key_bundle_bytes_list.iter()) {
            all_bundles.push((member.clone(), bytes.clone()));
        }

        let mut members_after = self.group_ref()?.members.clone();
        for member in member_names {
            if !members_after.contains(member) {
                members_after.push(member.clone());
            }
        }
        members_after.sort();

        self.build_group_change("add", members_after, member_names, &all_bundles)
    }

    pub fn remove_members(
        &mut self,
        target_names: &[String],
        recipient_pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<EpochChangeOutput> {
        let current_members = self.group_ref()?.members.clone();
        for target in target_names {
            if !current_members.contains(target) {
                return Err(anyhow!("Signal group member '{}' not found", target));
            }
        }

        let mut members_after: Vec<String> = current_members
            .into_iter()
            .filter(|member| !target_names.contains(member))
            .collect();
        members_after.sort();

        self.build_group_change("remove", members_after, &[], recipient_pre_key_bundles)
    }

    pub fn self_update(
        &mut self,
        recipient_pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<EpochChangeOutput> {
        let members_after = self.group_ref()?.members.clone();
        self.build_group_change("update", members_after, &[], recipient_pre_key_bundles)
    }

    pub fn rollback_pending_commit(&mut self) -> Result<()> {
        self.clear_pending_local_state();
        Ok(())
    }

    pub fn join_from_group_invite(&mut self, invite_bytes: &[u8]) -> Result<()> {
        let invite: GroupInviteEnvelope = bincode::deserialize(invite_bytes)
            .context("Could not deserialize Signal group invite")?;
        let plaintext =
            self.decrypt_from_sender(&invite.inviter, invite.message_type, &invite.ciphertext)?;
        let group_invite: GroupInvitePlaintext = bincode::deserialize(&plaintext)
            .context("Could not deserialize decrypted Signal group invite")?;

        if !group_invite.members.contains(&self.name) {
            return Err(anyhow!(
                "Signal group invite for group '{}' does not include this client",
                group_invite.group_id
            ));
        }

        self.group = Some(GroupState {
            group_id: group_invite.group_id,
            epoch: group_invite.epoch,
            members: group_invite.members,
        });

        Ok(())
    }

    pub fn send_application_message(
        &mut self,
        plaintext: &[u8],
        recipient_pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<Vec<u8>> {
        let group = self.group_ref()?.clone();
        let recipients: Vec<String> = group
            .members
            .iter()
            .filter(|member| *member != &self.name)
            .cloned()
            .collect();
        let bundle_map = Self::bundle_map(recipient_pre_key_bundles);

        let scope = ProfileScope::start("application_message_create", "libsignal-x3dh");
        let plaintext_len = plaintext.len();
        let epoch = group.epoch;
        let member_count = group.members.len();

        let mut measured_result: Option<Result<Vec<u8>>> = None;
        let allocation_info = measure(|| {
            measured_result = Some((|| {
                let mut ciphertexts = Vec::with_capacity(recipients.len());
                for recipient in &recipients {
                    ciphertexts.push(self.encrypt_for_recipient(
                        recipient,
                        plaintext,
                        bundle_map.get(recipient).map(Vec::as_slice),
                    )?);
                }

                let envelope = GroupApplicationEnvelope {
                    group_id: group.group_id.clone(),
                    epoch: group.epoch,
                    sender: self.name.clone(),
                    ciphertexts,
                };

                Ok::<_, anyhow::Error>(bincode::serialize(&envelope)?)
            })());
        });

        let bytes = measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to create pairwise Signal group application message")?;

        finish_and_emit(scope, |event| {
            event.group_epoch = Some(epoch);
            event.member_count = Some(member_count);
            event.ciphersuite = Some(self.session_protocol.label().to_string());
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.artifact_size_bytes = Some(bytes.len());
            event.app_msg_plaintext_bytes = Some(plaintext_len);
            event.app_msg_ciphertext_bytes = Some(bytes.len());
            event.aad_bytes = Some(0);
        });

        Ok(bytes)
    }

    pub fn receive_application_message(
        &mut self,
        message_bytes: &[u8],
        profile: bool,
    ) -> Result<Vec<u8>> {
        let group = self.group_ref()?.clone();
        let envelope: GroupApplicationEnvelope = bincode::deserialize(message_bytes)
            .context("Could not deserialize pairwise Signal application envelope")?;

        if envelope.group_id != group.group_id {
            return Err(anyhow!(
                "Signal application message group mismatch: expected {}, got {}",
                group.group_id,
                envelope.group_id
            ));
        }

        let ciphertext = envelope
            .ciphertexts
            .iter()
            .find(|ciphertext| ciphertext.recipient == self.name)
            .ok_or_else(|| anyhow!("No pairwise Signal ciphertext for {}", self.name))?;

        let scope = if profile {
            ProfileScope::start("application_message_receive", "libsignal-x3dh")
        } else {
            None
        };

        let mut measured_result: Option<Result<Vec<u8>>> = None;
        let allocation_info = measure(|| {
            measured_result = Some(self.decrypt_from_sender(
                &envelope.sender,
                ciphertext.message_type,
                &ciphertext.ciphertext,
            ));
        });

        let plaintext = measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to decrypt pairwise Signal application message")?;

        finish_and_emit(scope, |event| {
            event.group_epoch = Some(group.epoch);
            event.member_count = Some(group.members.len());
            event.ciphersuite = Some(self.session_protocol.label().to_string());
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.app_msg_plaintext_bytes = Some(plaintext.len());
            event.app_msg_ciphertext_bytes = Some(ciphertext.ciphertext.len());
            event.aad_bytes = Some(0);
        });

        Ok(plaintext)
    }

    pub fn receive_commit(&mut self, commit_bytes: &[u8]) -> Result<CommitReceiveOutcome> {
        let is_own_pending_commit = self
            .pending_commit_bytes
            .as_ref()
            .map(|pending| pending.as_slice() == commit_bytes)
            .unwrap_or(false);

        if is_own_pending_commit {
            let Some(group_after) = self.pending_group_after.take() else {
                return Err(anyhow!("Missing pending Signal group state for own change"));
            };

            let self_removed = !group_after.members.contains(&self.name);
            let group_invites = std::mem::take(&mut self.pending_group_invites);
            self.pending_commit_bytes = None;

            if self_removed {
                self.reset_local_state_fully()?;
            } else {
                self.group = Some(group_after);
            }

            return Ok(CommitReceiveOutcome::OwnChangeAccepted {
                self_removed,
                group_invites,
            });
        }

        let change: GroupChangeEnvelope = bincode::deserialize(commit_bytes)
            .context("Could not deserialize Signal group change")?;
        let current = self.group_ref()?.clone();

        if change.group_id != current.group_id || change.from_epoch != current.epoch {
            return Err(anyhow!(
                "Signal group change mismatch: expected group {} epoch {}, got group {} epoch {}",
                current.group_id,
                current.epoch,
                change.group_id,
                change.from_epoch
            ));
        }

        if !change.members_after.contains(&self.name) {
            self.reset_local_state_fully()?;
            return Ok(CommitReceiveOutcome::ExternalChangeApplied { self_removed: true });
        }

        let ciphertext = change
            .ciphertexts
            .iter()
            .find(|ciphertext| ciphertext.recipient == self.name)
            .ok_or_else(|| {
                anyhow!(
                    "No pairwise Signal group-control ciphertext for {}",
                    self.name
                )
            })?;

        let plaintext = self.decrypt_from_sender(
            &change.sender,
            ciphertext.message_type,
            &ciphertext.ciphertext,
        )?;
        let control: GroupControlPlaintext = bincode::deserialize(&plaintext)
            .context("Could not deserialize decrypted Signal group control message")?;

        if control.group_id != change.group_id
            || control.from_epoch != change.from_epoch
            || control.to_epoch != change.to_epoch
            || control.members_after != change.members_after
        {
            return Err(anyhow!(
                "Encrypted Signal group control did not match clear envelope"
            ));
        }

        self.group = Some(GroupState {
            group_id: change.group_id,
            epoch: change.to_epoch,
            members: change.members_after,
        });

        Ok(CommitReceiveOutcome::ExternalChangeApplied {
            self_removed: false,
        })
    }
}

impl PairwiseSession {
    fn new(root_key: &[u8; 32], local_name: &str, remote_name: &str) -> Self {
        Self {
            send_chain_key: derive_directional_chain(root_key, local_name, remote_name),
            recv_chain_key: derive_directional_chain(root_key, remote_name, local_name),
            send_counter: 0,
            recv_counter: 0,
        }
    }

    fn next_send_message_keys(&mut self) -> MessageKeys {
        let keys = derive_message_keys(&self.send_chain_key, self.send_counter);
        self.send_chain_key = advance_chain_key(&self.send_chain_key);
        self.send_counter = self.send_counter.saturating_add(1);
        keys
    }

    fn next_recv_message_keys(&mut self) -> MessageKeys {
        let keys = derive_message_keys(&self.recv_chain_key, self.recv_counter);
        self.recv_chain_key = advance_chain_key(&self.recv_chain_key);
        self.recv_counter = self.recv_counter.saturating_add(1);
        keys
    }
}

struct MessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
}

fn decode_pre_key_bundle(bytes: &[u8]) -> Result<WirePreKeyBundle> {
    let wire: WirePreKeyBundle =
        bincode::deserialize(bytes).context("Could not deserialize Signal X3DH pre-key bundle")?;
    if wire.protocol != "x3dh" {
        return Err(anyhow!(
            "Unsupported Signal pre-key protocol '{}'",
            wire.protocol
        ));
    }
    Ok(wire)
}

fn derive_x3dh_initiator_root_key(
    our_identity: &KeyPair,
    our_base_key: &KeyPair,
    their_identity: &PublicKey,
    their_signed_pre_key: &PublicKey,
    their_one_time_pre_key: Option<&PublicKey>,
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&[0xff; 32]);
    push_dh(&mut ikm, &our_identity.private_key, their_signed_pre_key)?;
    push_dh(&mut ikm, &our_base_key.private_key, their_identity)?;
    push_dh(&mut ikm, &our_base_key.private_key, their_signed_pre_key)?;
    if let Some(one_time_pre_key) = their_one_time_pre_key {
        push_dh(&mut ikm, &our_base_key.private_key, one_time_pre_key)?;
    }
    hkdf_32(X3DH_LABEL, &ikm)
}

fn derive_x3dh_responder_root_key(
    our_identity: &KeyPair,
    our_signed_pre_key: &KeyPair,
    our_one_time_pre_key: Option<&KeyPair>,
    their_identity: &PublicKey,
    their_base_key: &PublicKey,
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&[0xff; 32]);
    push_dh(&mut ikm, &our_signed_pre_key.private_key, their_identity)?;
    push_dh(&mut ikm, &our_identity.private_key, their_base_key)?;
    push_dh(&mut ikm, &our_signed_pre_key.private_key, their_base_key)?;
    if let Some(one_time_pre_key) = our_one_time_pre_key {
        push_dh(&mut ikm, &one_time_pre_key.private_key, their_base_key)?;
    }
    hkdf_32(X3DH_LABEL, &ikm)
}

fn push_dh(out: &mut Vec<u8>, private_key: &PrivateKey, public_key: &PublicKey) -> Result<()> {
    out.extend_from_slice(&private_key.calculate_agreement(public_key)?);
    Ok(())
}

fn hkdf_32(info: &[u8], ikm: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow!("HKDF output length is invalid"))?;
    Ok(out)
}

fn derive_directional_chain(root_key: &[u8; 32], sender: &str, recipient: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(root_key);
    input.extend_from_slice(sender.as_bytes());
    input.push(0);
    input.extend_from_slice(recipient.as_bytes());
    hkdf_32(X3DH_CHAIN_LABEL, &input).expect("fixed HKDF output")
}

fn derive_message_keys(chain_key: &[u8; 32], counter: u64) -> MessageKeys {
    let mut input = Vec::new();
    input.extend_from_slice(chain_key);
    input.extend_from_slice(&counter.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(None, &input);
    let mut out = [0u8; 80];
    hk.expand(b"signal_playground_message_keys_v1", &mut out)
        .expect("fixed HKDF output");

    let mut cipher_key = [0u8; 32];
    cipher_key.copy_from_slice(&out[0..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&out[32..64]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&out[64..80]);

    MessageKeys {
        cipher_key,
        mac_key,
        iv,
    }
}

fn advance_chain_key(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(chain_key);
    hasher.update(b"signal_playground_advance_chain_v1");
    hasher.finalize().into()
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut mac = CryptographicMac::new("HmacSha256", key)
        .map_err(|err| anyhow!("Could not create HMAC-SHA256: {}", err))?;
    mac.update(input);
    Ok(mac.finalize())
}
