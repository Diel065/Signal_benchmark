use std::collections::{HashMap, HashSet};

use allocation_counter::measure;
use anyhow::{anyhow, Context, Result};
use libsignal_protocol::CiphertextMessageType;
use serde::{Deserialize, Serialize};

use crate::{
    debug::print_bytes,
    libsignal_pairwise::{inspect_encrypted_message, LibsignalPairwiseClient},
    profiling::{finish_and_emit, ProfileScope},
};

const SIGNAL_IMPLEMENTATION_LABEL: &str = "libsignal-main";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairwiseApplicationEnvelope {
    sender: String,
    message_type: u8,
    ciphertext: Vec<u8>,
}

pub struct Client {
    pub name: String,
    protocol: LibsignalPairwiseClient,
    highest_inbound_counter_by_sender: HashMap<String, u32>,
    seen_inbound_counters_by_sender: HashMap<String, HashSet<u32>>,
}

impl Client {
    pub fn new(name: &str) -> Result<Self> {
        let protocol = LibsignalPairwiseClient::new(name)?;
        let identity_public_key = protocol.identity_public_key_bytes()?;

        print_bytes(
            &format!("{} Signal identity public key", name),
            &identity_public_key,
        );
        print_bytes(&format!("{} Signal address bytes", name), name.as_bytes());

        Ok(Self {
            name: name.to_string(),
            protocol,
            highest_inbound_counter_by_sender: HashMap::new(),
            seen_inbound_counters_by_sender: HashMap::new(),
        })
    }

    pub fn generate_pre_key_bundle(&mut self) -> Result<Vec<u8>> {
        let scope = ProfileScope::start("generate_prekey_bundle", SIGNAL_IMPLEMENTATION_LABEL);

        let mut measured_result: Option<Result<Vec<u8>>> = None;
        let allocation_info = measure(|| {
            measured_result = Some(self.protocol.generate_pre_key_bundle());
        });

        let bytes = measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to generate libsignal pre-key bundle")?;

        finish_and_emit(scope, |event| {
            event.protocol_bytes = Some(bytes.len());
            event.wire_bytes = Some(bytes.len());
            event.harness_metadata_bytes = Some(0);
            event.ciphertext_count = Some(0);
            event.recipient_count = Some(0);
            event.fanout_recipients = Some(0);
            event.session_setup_count = Some(0);
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.ciphersuite = Some(self.protocol.ciphersuite_label().to_string());
            event.payload_class = Some("prekey_bundle".to_string());
        });

        print_bytes(&format!("{} Signal pre-key bundle", self.name), &bytes);
        Ok(bytes)
    }

    pub fn send_application_message(
        &mut self,
        plaintext: &[u8],
        recipients: &[String],
        recipient_pre_key_bundles: &[(String, Vec<u8>)],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        if recipients.is_empty() {
            return Err(anyhow!(
                "At least one recipient is required for Signal fanout"
            ));
        }

        let bundle_map: HashMap<String, Vec<u8>> =
            recipient_pre_key_bundles.iter().cloned().collect();

        let scope = ProfileScope::start("fanout_send_to_k_recipients", SIGNAL_IMPLEMENTATION_LABEL);
        let plaintext_len = plaintext.len();
        let participant_count = recipients.len() + 1;

        let mut measured_result: Option<
            Result<(
                Vec<(String, Vec<u8>)>,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
                Option<u32>,
            )>,
        > = None;
        let allocation_info = measure(|| {
            measured_result = Some((|| {
                let mut messages = Vec::with_capacity(recipients.len());
                let mut protocol_bytes = 0usize;
                let mut wire_bytes = 0usize;
                let mut ciphertext_count = 0usize;
                let mut session_setup_count = 0usize;
                let mut prekey_message_count = 0usize;
                let mut whisper_message_count = 0usize;
                let mut single_counter = None;

                for recipient in recipients {
                    let had_session = self.protocol.session_exists(recipient)?;
                    let encrypted = self.protocol.encrypt_to(
                        recipient,
                        plaintext,
                        bundle_map.get(recipient).map(Vec::as_slice),
                    )?;
                    if !had_session {
                        session_setup_count += 1;
                    }

                    protocol_bytes += encrypted.ciphertext.len();
                    ciphertext_count += 1;
                    prekey_message_count += usize::from(encrypted.is_prekey);
                    whisper_message_count += usize::from(!encrypted.is_prekey);
                    if recipients.len() == 1 {
                        single_counter = Some(encrypted.message_counter);
                    }

                    let envelope = PairwiseApplicationEnvelope {
                        sender: self.name.clone(),
                        message_type: encrypted.message_type,
                        ciphertext: encrypted.ciphertext,
                    };
                    let envelope_bytes = bincode::serialize(&envelope)?;
                    wire_bytes += envelope_bytes.len();
                    messages.push((recipient.clone(), envelope_bytes));
                }

                Ok::<_, anyhow::Error>((
                    messages,
                    protocol_bytes,
                    wire_bytes,
                    ciphertext_count,
                    session_setup_count,
                    prekey_message_count,
                    whisper_message_count,
                    single_counter,
                ))
            })());
        });

        let (
            messages,
            protocol_bytes,
            wire_bytes,
            ciphertext_count,
            session_setup_count,
            prekey_message_count,
            whisper_message_count,
            single_counter,
        ) = measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to create libsignal application fanout")?;

        finish_and_emit(scope, |event| {
            event.protocol_bytes = Some(protocol_bytes);
            event.wire_bytes = Some(wire_bytes);
            event.harness_metadata_bytes = Some(wire_bytes.saturating_sub(protocol_bytes));
            event.ciphertext_count = Some(ciphertext_count);
            event.recipient_count = Some(recipients.len());
            event.fanout_recipients = Some(recipients.len());
            event.session_setup_count = Some(session_setup_count);
            event.prekey_message_count = Some(prekey_message_count);
            event.whisper_message_count = Some(whisper_message_count);
            event.ratchet_message_counter = single_counter;
            event.participant_count = Some(participant_count);
            event.ciphersuite = Some(self.protocol.ciphersuite_label().to_string());
            event.alloc_bytes = Some(allocation_info.bytes_total as u64);
            event.alloc_count = Some(allocation_info.count_total as u64);
            event.app_msg_plaintext_bytes = Some(plaintext_len);
            event.app_msg_ciphertext_bytes = Some(protocol_bytes);
            event.aad_bytes = Some(0);
            event.payload_class = Some("application".to_string());
        });

        Ok(messages)
    }

    pub fn receive_application_message(
        &mut self,
        message_bytes: &[u8],
        profile: bool,
    ) -> Result<Vec<u8>> {
        let envelope: PairwiseApplicationEnvelope = bincode::deserialize(message_bytes)
            .context("Could not deserialize pairwise Signal application envelope")?;
        let session_setup_count =
            usize::from(envelope.message_type == CiphertextMessageType::PreKey as u8);
        let observability = inspect_encrypted_message(envelope.message_type, &envelope.ciphertext)
            .context("Could not inspect libsignal message observability")?;
        let ordering =
            self.classify_inbound_message(&envelope.sender, observability.message_counter);

        let scope = if profile {
            ProfileScope::start("fanout_receive_one", SIGNAL_IMPLEMENTATION_LABEL)
        } else {
            None
        };

        let mut measured_result: Option<Result<Vec<u8>>> = None;
        let allocation_info = measure(|| {
            measured_result = Some(self.protocol.decrypt_from(
                &envelope.sender,
                envelope.message_type,
                &envelope.ciphertext,
            ));
        });

        match measured_result
            .expect("allocation_counter measure closure did not run")
            .context("Failed to decrypt libsignal application message")
        {
            Ok(plaintext) => {
                self.record_successful_inbound_message(
                    &envelope.sender,
                    observability.message_counter,
                );

                finish_and_emit(scope, |event| {
                    fill_receive_event(
                        event,
                        message_bytes,
                        &envelope,
                        session_setup_count,
                        &observability,
                        &ordering,
                        Some(plaintext.len()),
                        allocation_info.bytes_total as u64,
                        allocation_info.count_total as u64,
                        self.protocol.ciphersuite_label(),
                    );
                });

                Ok(plaintext)
            }
            Err(err) => {
                finish_and_emit(scope, |event| {
                    event.success = false;
                    fill_receive_event(
                        event,
                        message_bytes,
                        &envelope,
                        session_setup_count,
                        &observability,
                        &ordering,
                        None,
                        allocation_info.bytes_total as u64,
                        allocation_info.count_total as u64,
                        self.protocol.ciphersuite_label(),
                    );
                });

                Err(err)
            }
        }
    }

    pub fn session_exists(&self, peer: &str) -> Result<bool> {
        self.protocol.session_exists(peer)
    }

    fn classify_inbound_message(&self, sender: &str, counter: u32) -> InboundOrderingObservation {
        let duplicate = self
            .seen_inbound_counters_by_sender
            .get(sender)
            .map(|seen| seen.contains(&counter))
            .unwrap_or(false);
        let out_of_order = self
            .highest_inbound_counter_by_sender
            .get(sender)
            .map(|highest| counter < *highest && !duplicate)
            .unwrap_or(false);

        InboundOrderingObservation {
            out_of_order,
            duplicate,
        }
    }

    fn record_successful_inbound_message(&mut self, sender: &str, counter: u32) {
        self.highest_inbound_counter_by_sender
            .entry(sender.to_string())
            .and_modify(|highest| {
                *highest = (*highest).max(counter);
            })
            .or_insert(counter);
        self.seen_inbound_counters_by_sender
            .entry(sender.to_string())
            .or_default()
            .insert(counter);
    }
}

#[derive(Clone, Copy)]
struct InboundOrderingObservation {
    out_of_order: bool,
    duplicate: bool,
}

fn fill_receive_event(
    event: &mut crate::profiling::ProfileEvent,
    message_bytes: &[u8],
    envelope: &PairwiseApplicationEnvelope,
    session_setup_count: usize,
    observability: &crate::libsignal_pairwise::MessageObservability,
    ordering: &InboundOrderingObservation,
    plaintext_len: Option<usize>,
    alloc_bytes: u64,
    alloc_count: u64,
    ciphersuite_label: &str,
) {
    event.protocol_bytes = Some(envelope.ciphertext.len());
    event.wire_bytes = Some(message_bytes.len());
    event.harness_metadata_bytes = Some(
        message_bytes
            .len()
            .saturating_sub(envelope.ciphertext.len()),
    );
    event.ciphertext_count = Some(1);
    event.recipient_count = Some(1);
    event.fanout_recipients = Some(1);
    event.session_setup_count = Some(session_setup_count);
    event.prekey_message_count = Some(usize::from(observability.is_prekey));
    event.whisper_message_count = Some(usize::from(!observability.is_prekey));
    event.ratchet_message_counter = Some(observability.message_counter);
    event.out_of_order_messages_seen = Some(usize::from(ordering.out_of_order));
    event.duplicate_messages_seen = Some(usize::from(ordering.duplicate));
    event.participant_count = Some(2);
    event.ciphersuite = Some(ciphersuite_label.to_string());
    event.alloc_bytes = Some(alloc_bytes);
    event.alloc_count = Some(alloc_count);
    event.app_msg_plaintext_bytes = plaintext_len;
    event.app_msg_ciphertext_bytes = Some(envelope.ciphertext.len());
    event.aad_bytes = Some(0);
    event.payload_class = Some("application".to_string());
}
