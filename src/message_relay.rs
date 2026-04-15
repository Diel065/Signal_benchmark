use std::collections::{HashMap, VecDeque};

pub struct MessageRelay {
    inboxes: HashMap<String, VecDeque<Vec<u8>>>,
}

impl MessageRelay {
    pub fn new() -> Self {
        Self {
            inboxes: HashMap::new(),
        }
    }

    pub fn publish_message(&mut self, recipient: &str, message_bytes: Vec<u8>) {
        self.inboxes
            .entry(recipient.to_string())
            .or_default()
            .push_back(message_bytes);
    }

    pub fn fetch_message(&mut self, recipient: &str) -> Option<Vec<u8>> {
        self.inboxes
            .get_mut(recipient)
            .and_then(|queue| queue.pop_front())
    }
}
