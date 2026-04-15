use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use futures::executor::block_on;
use libsignal_protocol::{
    kem, message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle, PreKeyBundleContent, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, PublicKey, SessionStore, SignalMessage, SignedPreKeyRecord, SignedPreKeyStore,
    Timestamp,
};
use rand::{rng, Rng as _};
use serde::{Deserialize, Serialize};

const DEFAULT_DEVICE_ID: u8 = 1;
const SIGNAL_CIPHERSUITE_LABEL: &str = "Signal PQXDH + Double Ratchet (libsignal-main)";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key_id: Option<u32>,
    pub pre_key_public: Option<Vec<u8>>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: Vec<u8>,
    pub signed_pre_key_signature: Vec<u8>,
    pub identity_key: Vec<u8>,
    pub kyber_pre_key_id: u32,
    pub kyber_pre_key_public: Vec<u8>,
    pub kyber_pre_key_signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct WireEncryptedMessage {
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
    pub is_prekey: bool,
    pub message_counter: u32,
}

#[derive(Clone, Debug)]
pub struct MessageObservability {
    pub is_prekey: bool,
    pub message_counter: u32,
}

pub struct LibsignalPairwiseClient {
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    next_kyber_pre_key_id: u32,
}

impl LibsignalPairwiseClient {
    pub fn new(name: &str) -> Result<Self> {
        let mut csprng = rng();
        let identity_key = IdentityKeyPair::generate(&mut csprng);
        let registration_id = (csprng.random::<u32>() & 0x3fff).max(1);
        let device_id = DeviceId::try_from(u32::from(DEFAULT_DEVICE_ID))
            .context("Could not construct libsignal device id")?;
        let address = ProtocolAddress::new(name.to_string(), device_id);
        let store = InMemSignalProtocolStore::new(identity_key, registration_id)
            .context("Could not initialize libsignal protocol store")?;

        Ok(Self {
            address,
            store,
            next_pre_key_id: 1,
            next_signed_pre_key_id: 1,
            next_kyber_pre_key_id: 1,
        })
    }

    pub fn ciphersuite_label(&self) -> &'static str {
        SIGNAL_CIPHERSUITE_LABEL
    }

    pub fn identity_public_key_bytes(&self) -> Result<Vec<u8>> {
        let identity_key_pair = block_on(self.store.get_identity_key_pair())
            .context("Could not load libsignal identity key pair")?;
        Ok(identity_key_pair.identity_key().serialize().into_vec())
    }

    pub fn generate_pre_key_bundle(&mut self) -> Result<Vec<u8>> {
        let bundle = self.build_pre_key_bundle()?;
        encode_pre_key_bundle(bundle)
    }

    pub fn encrypt_to(
        &mut self,
        recipient: &str,
        plaintext: &[u8],
        pre_key_bundle_bytes: Option<&[u8]>,
    ) -> Result<WireEncryptedMessage> {
        let remote_address = self.protocol_address(recipient);
        if !self.session_exists(recipient)? {
            let bundle = decode_pre_key_bundle(pre_key_bundle_bytes.ok_or_else(|| {
                anyhow!("Missing pre-key bundle for Signal peer '{}'", recipient)
            })?)?;
            let mut csprng = rng();
            let store = &mut self.store;
            block_on(process_prekey_bundle(
                &remote_address,
                &mut store.session_store,
                &mut store.identity_store,
                &bundle,
                SystemTime::now(),
                &mut csprng,
            ))
            .with_context(|| {
                format!(
                    "Could not process libsignal pre-key bundle for {}",
                    recipient
                )
            })?;
        }

        let mut csprng = rng();
        let store = &mut self.store;
        let ciphertext = block_on(message_encrypt(
            plaintext,
            &remote_address,
            &self.address,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            &mut csprng,
        ))
        .with_context(|| format!("Could not encrypt libsignal message for {}", recipient))?;
        let observability = observe_ciphertext_message(&ciphertext);

        Ok(WireEncryptedMessage {
            message_type: ciphertext.message_type() as u8,
            ciphertext: ciphertext.serialize().to_vec(),
            is_prekey: observability.is_prekey,
            message_counter: observability.message_counter,
        })
    }

    pub fn decrypt_from(
        &mut self,
        sender: &str,
        message_type: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let remote_address = self.protocol_address(sender);
        let incoming_message = decode_ciphertext_message(message_type, ciphertext)?;
        let mut csprng = rng();
        let store = &mut self.store;

        block_on(message_decrypt(
            &incoming_message,
            &remote_address,
            &self.address,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut csprng,
        ))
        .with_context(|| format!("Could not decrypt libsignal message from {}", sender))
    }

    pub fn session_exists(&self, peer: &str) -> Result<bool> {
        let remote_address = self.protocol_address(peer);
        Ok(block_on(self.store.load_session(&remote_address))
            .with_context(|| format!("Could not load libsignal session for {}", peer))?
            .is_some())
    }

    pub fn has_local_one_time_pre_key(&self, pre_key_id: u32) -> Result<bool> {
        Ok(block_on(self.store.pre_key_store.get_pre_key(pre_key_id.into())).is_ok())
    }

    fn protocol_address(&self, name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_string(), self.address.device_id())
    }

    fn build_pre_key_bundle(&mut self) -> Result<PreKeyBundle> {
        let mut csprng = rng();
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);

        let identity_key_pair = block_on(self.store.get_identity_key_pair())
            .context("Could not load libsignal identity key pair")?;
        let registration_id = block_on(self.store.get_local_registration_id())
            .context("Could not load libsignal registration id")?;

        let pre_key_id = self.next_pre_key_id;
        self.next_pre_key_id = self.next_pre_key_id.saturating_add(1);

        let signed_pre_key_id = self.next_signed_pre_key_id;
        self.next_signed_pre_key_id = self.next_signed_pre_key_id.saturating_add(1);

        let kyber_pre_key_id = self.next_kyber_pre_key_id;
        self.next_kyber_pre_key_id = self.next_kyber_pre_key_id.saturating_add(1);

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut csprng)?
            .into_vec();

        let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
        let kyber_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&kyber_pre_key_public, &mut csprng)?
            .into_vec();

        let timestamp = current_timestamp()?;

        block_on(self.store.save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
        ))
        .context("Could not save libsignal pre-key record")?;

        block_on(self.store.save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                timestamp,
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        ))
        .context("Could not save libsignal signed pre-key record")?;

        block_on(self.store.save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                kyber_pre_key_id.into(),
                timestamp,
                &kyber_pre_key_pair,
                &kyber_pre_key_signature,
            ),
        ))
        .context("Could not save libsignal kyber pre-key record")?;

        PreKeyBundle::new(
            registration_id,
            self.address.device_id(),
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            signed_pre_key_signature,
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key,
            kyber_pre_key_signature,
            *identity_key_pair.identity_key(),
        )
        .context("Could not build libsignal pre-key bundle")
    }
}

pub fn inspect_encrypted_message(
    message_type: u8,
    ciphertext: &[u8],
) -> Result<MessageObservability> {
    let message = decode_ciphertext_message(message_type, ciphertext)?;
    Ok(observe_ciphertext_message(&message))
}

fn current_timestamp() -> Result<Timestamp> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_millis();
    let millis = u64::try_from(millis).context("Timestamp does not fit into u64")?;
    Ok(Timestamp::from_epoch_millis(millis))
}

pub fn encode_wire_pre_key_bundle(wire: &WirePreKeyBundle) -> Result<Vec<u8>> {
    Ok(bincode::serialize(wire)?)
}

pub fn decode_wire_pre_key_bundle(bytes: &[u8]) -> Result<WirePreKeyBundle> {
    bincode::deserialize(bytes).context("Could not deserialize libsignal pre-key bundle")
}

fn encode_pre_key_bundle(bundle: PreKeyBundle) -> Result<Vec<u8>> {
    let content: PreKeyBundleContent = bundle.into();
    let wire = WirePreKeyBundle {
        registration_id: content
            .registration_id
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing registration_id"))?,
        device_id: u32::from(
            content
                .device_id
                .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing device_id"))?,
        ),
        pre_key_id: content.pre_key_id.map(Into::into),
        pre_key_public: content
            .pre_key_public
            .map(|public_key| public_key.serialize().to_vec()),
        signed_pre_key_id: content
            .signed_pre_key_id
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing signed_pre_key_id"))?
            .into(),
        signed_pre_key_public: content
            .signed_pre_key_public
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing signed_pre_key_public"))?
            .serialize()
            .to_vec(),
        signed_pre_key_signature: content.signed_pre_key_signature.ok_or_else(|| {
            anyhow!("libsignal pre-key bundle is missing signed_pre_key_signature")
        })?,
        identity_key: content
            .identity_key
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing identity_key"))?
            .serialize()
            .into_vec(),
        kyber_pre_key_id: content
            .kyber_pre_key_id
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing kyber_pre_key_id"))?
            .into(),
        kyber_pre_key_public: content
            .kyber_pre_key_public
            .ok_or_else(|| anyhow!("libsignal pre-key bundle is missing kyber_pre_key_public"))?
            .serialize()
            .to_vec(),
        kyber_pre_key_signature: content.kyber_pre_key_signature.ok_or_else(|| {
            anyhow!("libsignal pre-key bundle is missing kyber_pre_key_signature")
        })?,
    };

    encode_wire_pre_key_bundle(&wire)
}

fn decode_pre_key_bundle(bytes: &[u8]) -> Result<PreKeyBundle> {
    let wire = decode_wire_pre_key_bundle(bytes)?;

    let content = PreKeyBundleContent {
        registration_id: Some(wire.registration_id),
        device_id: Some(
            DeviceId::try_from(wire.device_id)
                .context("Could not deserialize libsignal device id")?,
        ),
        pre_key_id: wire.pre_key_id.map(Into::into),
        pre_key_public: wire
            .pre_key_public
            .map(|bytes| PublicKey::deserialize(&bytes))
            .transpose()
            .context("Could not deserialize libsignal pre-key public key")?,
        signed_pre_key_id: Some(wire.signed_pre_key_id.into()),
        signed_pre_key_public: Some(
            PublicKey::deserialize(&wire.signed_pre_key_public)
                .context("Could not deserialize libsignal signed pre-key public key")?,
        ),
        signed_pre_key_signature: Some(wire.signed_pre_key_signature),
        identity_key: Some(
            IdentityKey::try_from(wire.identity_key.as_slice())
                .context("Could not deserialize libsignal identity key")?,
        ),
        kyber_pre_key_id: Some(wire.kyber_pre_key_id.into()),
        kyber_pre_key_public: Some(
            kem::PublicKey::deserialize(&wire.kyber_pre_key_public)
                .context("Could not deserialize libsignal kyber pre-key public key")?,
        ),
        kyber_pre_key_signature: Some(wire.kyber_pre_key_signature),
    };

    content
        .try_into()
        .context("Could not reconstruct libsignal pre-key bundle")
}

fn decode_ciphertext_message(message_type: u8, ciphertext: &[u8]) -> Result<CiphertextMessage> {
    let message_type = CiphertextMessageType::try_from(message_type)
        .map_err(|_| anyhow!("Unsupported Signal message type {}", message_type))?;

    match message_type {
        CiphertextMessageType::Whisper => Ok(CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext)
                .context("Could not deserialize libsignal SignalMessage")?,
        )),
        CiphertextMessageType::PreKey => Ok(CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext)
                .context("Could not deserialize libsignal PreKeySignalMessage")?,
        )),
        other => Err(anyhow!(
            "Unsupported pairwise libsignal ciphertext type {:?}",
            other
        )),
    }
}

fn observe_ciphertext_message(message: &CiphertextMessage) -> MessageObservability {
    match message {
        CiphertextMessage::SignalMessage(message) => MessageObservability {
            is_prekey: false,
            message_counter: message.counter(),
        },
        CiphertextMessage::PreKeySignalMessage(message) => MessageObservability {
            is_prekey: true,
            message_counter: message.message().counter(),
        },
        other => unreachable!(
            "unsupported pairwise message type {:?}",
            other.message_type()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::CiphertextMessageType;

    #[test]
    fn pre_key_bundle_round_trip_preserves_wire_bytes() -> Result<()> {
        let mut alice = LibsignalPairwiseClient::new("alice")?;
        let bytes = alice.generate_pre_key_bundle()?;
        let round_trip = encode_pre_key_bundle(decode_pre_key_bundle(&bytes)?)?;
        assert_eq!(bytes, round_trip);
        Ok(())
    }

    #[test]
    fn libsignal_round_trip_establishes_pairwise_session() -> Result<()> {
        let mut alice = LibsignalPairwiseClient::new("alice")?;
        let mut bob = LibsignalPairwiseClient::new("bob")?;

        let bob_bundle = bob.generate_pre_key_bundle()?;
        assert!(!alice.session_exists("bob")?);

        let first = alice.encrypt_to("bob", b"hello", Some(&bob_bundle))?;
        assert_eq!(first.message_type, CiphertextMessageType::PreKey as u8);

        let first_plaintext = bob.decrypt_from("alice", first.message_type, &first.ciphertext)?;
        assert_eq!(first_plaintext, b"hello");
        assert!(alice.session_exists("bob")?);
        assert!(bob.session_exists("alice")?);

        let second = alice.encrypt_to("bob", b"again", None)?;
        let second_plaintext =
            bob.decrypt_from("alice", second.message_type, &second.ciphertext)?;
        assert_eq!(second_plaintext, b"again");

        Ok(())
    }

    #[test]
    fn libsignal_accepts_out_of_order_messages_and_rejects_duplicates() -> Result<()> {
        let mut alice = LibsignalPairwiseClient::new("alice")?;
        let mut bob = LibsignalPairwiseClient::new("bob")?;

        let bob_bundle = bob.generate_pre_key_bundle()?;
        let setup = alice.encrypt_to("bob", b"setup", Some(&bob_bundle))?;
        assert_eq!(
            bob.decrypt_from("alice", setup.message_type, &setup.ciphertext)?,
            b"setup"
        );

        let ack = bob.encrypt_to("alice", b"ack", None)?;
        assert_eq!(
            alice.decrypt_from("bob", ack.message_type, &ack.ciphertext)?,
            b"ack"
        );

        let first = alice.encrypt_to("bob", b"one", None)?;
        let second = alice.encrypt_to("bob", b"two", None)?;
        let third = alice.encrypt_to("bob", b"three", None)?;

        assert_eq!(
            bob.decrypt_from("alice", second.message_type, &second.ciphertext)?,
            b"two"
        );
        assert_eq!(
            bob.decrypt_from("alice", first.message_type, &first.ciphertext)?,
            b"one"
        );
        assert_eq!(
            bob.decrypt_from("alice", third.message_type, &third.ciphertext)?,
            b"three"
        );
        assert!(bob
            .decrypt_from("alice", second.message_type, &second.ciphertext)
            .is_err());

        Ok(())
    }
}
