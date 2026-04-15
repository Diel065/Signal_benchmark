use std::collections::HashMap;

use anyhow::Result;

use crate::libsignal_pairwise::{
    decode_wire_pre_key_bundle, encode_wire_pre_key_bundle, WirePreKeyBundle,
};

pub struct FetchOutcome {
    pub bytes: Vec<u8>,
    pub opk_present: bool,
    pub opk_consumed: bool,
}

pub struct KeyRepository {
    pre_key_bundles: HashMap<String, WirePreKeyBundle>,
}

impl KeyRepository {
    pub fn new() -> Self {
        Self {
            pre_key_bundles: HashMap::new(),
        }
    }

    pub fn publish_pre_key_bundle(
        &mut self,
        owner: &str,
        pre_key_bundle_bytes: Vec<u8>,
    ) -> Result<()> {
        let bundle = decode_wire_pre_key_bundle(&pre_key_bundle_bytes)?;
        self.pre_key_bundles.insert(owner.to_string(), bundle);
        Ok(())
    }

    pub fn fetch_pre_key_bundle(&mut self, owner: &str) -> Result<Option<FetchOutcome>> {
        let Some(stored_bundle) = self.pre_key_bundles.get_mut(owner) else {
            return Ok(None);
        };

        let opk_present =
            stored_bundle.pre_key_id.is_some() && stored_bundle.pre_key_public.is_some();
        let response_bundle = stored_bundle.clone();

        if opk_present {
            stored_bundle.pre_key_id = None;
            stored_bundle.pre_key_public = None;
        }

        Ok(Some(FetchOutcome {
            bytes: encode_wire_pre_key_bundle(&response_bundle)?,
            opk_present,
            opk_consumed: opk_present,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libsignal_pairwise::{LibsignalPairwiseClient, WireEncryptedMessage};

    fn decrypt(
        receiver: &mut LibsignalPairwiseClient,
        sender_name: &str,
        message: &WireEncryptedMessage,
    ) -> Result<Vec<u8>> {
        receiver.decrypt_from(sender_name, message.message_type, &message.ciphertext)
    }

    #[test]
    fn fetch_consumes_opk_and_preserves_no_opk_fallback() -> Result<()> {
        let mut repository = KeyRepository::new();
        let mut bob = LibsignalPairwiseClient::new("bob")?;

        repository.publish_pre_key_bundle("bob", bob.generate_pre_key_bundle()?)?;

        let first = repository
            .fetch_pre_key_bundle("bob")?
            .expect("bundle exists");
        assert!(first.opk_present);
        assert!(first.opk_consumed);
        let first_bundle = decode_wire_pre_key_bundle(&first.bytes)?;
        let first_pre_key_id = first_bundle
            .pre_key_id
            .expect("first fetch should include OPK");
        assert!(first_bundle.pre_key_public.is_some());

        let second = repository
            .fetch_pre_key_bundle("bob")?
            .expect("bundle exists");
        assert!(!second.opk_present);
        assert!(!second.opk_consumed);
        let second_bundle = decode_wire_pre_key_bundle(&second.bytes)?;
        assert!(second_bundle.pre_key_id.is_none());
        assert!(second_bundle.pre_key_public.is_none());

        let mut alice = LibsignalPairwiseClient::new("alice")?;
        let first_message = alice.encrypt_to("bob", b"hello", Some(&first.bytes))?;
        assert_eq!(decrypt(&mut bob, "alice", &first_message)?, b"hello");
        assert!(!bob.has_local_one_time_pre_key(first_pre_key_id)?);

        let mut carol = LibsignalPairwiseClient::new("carol")?;
        let second_message = carol.encrypt_to("bob", b"fallback", Some(&second.bytes))?;
        assert_eq!(decrypt(&mut bob, "carol", &second_message)?, b"fallback");

        let mut dave = LibsignalPairwiseClient::new("dave")?;
        let stale_message = dave.encrypt_to("bob", b"stale", Some(&first.bytes))?;
        assert!(decrypt(&mut bob, "dave", &stale_message).is_err());

        Ok(())
    }
}
