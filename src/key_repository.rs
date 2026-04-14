use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct GroupInfo {
    pub current_epoch: u64,
    pub members: Vec<String>,
}

#[derive(Clone, Debug)]
struct GroupState {
    current_epoch: u64,
    members: Vec<String>,
}

pub struct KeyRepository {
    pre_key_bundles: HashMap<String, Vec<u8>>,
    group_change_inboxes: HashMap<String, VecDeque<Vec<u8>>>,
    group_invite_inboxes: HashMap<String, VecDeque<Vec<u8>>>,
    groups: HashMap<String, GroupState>,
}

impl KeyRepository {
    pub fn new() -> Self {
        Self {
            pre_key_bundles: HashMap::new(),
            group_change_inboxes: HashMap::new(),
            group_invite_inboxes: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    pub fn publish_pre_key_bundle(&mut self, owner: &str, pre_key_bundle_bytes: Vec<u8>) {
        self.pre_key_bundles
            .insert(owner.to_string(), pre_key_bundle_bytes);
    }

    pub fn fetch_pre_key_bundle(&self, owner: &str) -> Option<Vec<u8>> {
        self.pre_key_bundles.get(owner).cloned()
    }

    pub fn put_group_state(
        &mut self,
        group_id: &str,
        epoch: u64,
        members: Vec<String>,
    ) -> Result<(), String> {
        match self.groups.get_mut(group_id) {
            Some(state) => {
                if epoch != state.current_epoch {
                    return Err(format!(
                        "Group state update mismatch for group '{}': expected epoch {}, got {}",
                        group_id, state.current_epoch, epoch
                    ));
                }

                state.members = members;
                Ok(())
            }
            None => {
                self.groups.insert(
                    group_id.to_string(),
                    GroupState {
                        current_epoch: epoch,
                        members,
                    },
                );
                Ok(())
            }
        }
    }

    pub fn get_group_state(&self, group_id: &str) -> Option<GroupInfo> {
        self.groups.get(group_id).map(|state| GroupInfo {
            current_epoch: state.current_epoch,
            members: state.members.clone(),
        })
    }

    pub fn publish_group_change(
        &mut self,
        group_id: &str,
        sender: &str,
        epoch: u64,
        change_bytes: Vec<u8>,
    ) -> Result<(), String> {
        let state = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| format!("Unknown group_id '{}'", group_id))?;

        if epoch != state.current_epoch {
            return Err(format!(
                "Group change epoch mismatch for group '{}': expected {}, got {}",
                group_id, state.current_epoch, epoch
            ));
        }

        for recipient in state.members.clone() {
            self.group_change_inboxes
                .entry(recipient)
                .or_default()
                .push_back(change_bytes.clone());
        }

        state.current_epoch += 1;

        println!(
            "[KEY-REPO] Accepted group change for group={} epoch={} from sender={}",
            group_id, epoch, sender
        );

        Ok(())
    }

    pub fn fetch_group_change(&mut self, recipient: &str) -> Option<Vec<u8>> {
        self.group_change_inboxes
            .get_mut(recipient)
            .and_then(|queue| queue.pop_front())
    }

    pub fn publish_group_invite(&mut self, recipient: &str, invite_bytes: Vec<u8>) {
        self.group_invite_inboxes
            .entry(recipient.to_string())
            .or_default()
            .push_back(invite_bytes);
    }

    pub fn fetch_group_invite(&mut self, recipient: &str) -> Option<Vec<u8>> {
        self.group_invite_inboxes
            .get_mut(recipient)
            .and_then(|queue| queue.pop_front())
    }
}
