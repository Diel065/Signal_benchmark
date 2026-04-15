use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use cpu_time::ThreadTime;
use serde::Serialize;

static PROFILE_WRITER: OnceLock<Option<Mutex<BufWriter<File>>>> = OnceLock::new();

fn profile_path() -> Option<PathBuf> {
    std::env::var_os("SIGNAL_PROFILE_PATH").map(PathBuf::from)
}

fn writer() -> &'static Option<Mutex<BufWriter<File>>> {
    PROFILE_WRITER.get_or_init(|| {
        let path = match profile_path() {
            Some(p) => p,
            None => return None,
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;

        Some(Mutex::new(BufWriter::new(file)))
    })
}

fn unix_timestamp_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn env_or_none(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

pub fn profiling_enabled() -> bool {
    writer().is_some()
}

#[derive(Serialize, Debug)]
pub struct ProfileEvent {
    pub ts_unix_ns: u128,
    pub op: String,
    pub implementation: String,

    pub wall_ns: u128,
    pub cpu_thread_ns: Option<u128>,

    pub alloc_bytes: Option<u64>,
    pub alloc_count: Option<u64>,

    pub success: bool,
    pub protocol_bytes: Option<usize>,
    pub wire_bytes: Option<usize>,
    pub harness_metadata_bytes: Option<usize>,
    pub ciphertext_count: Option<usize>,
    pub recipient_count: Option<usize>,
    pub fanout_recipients: Option<usize>,
    pub session_setup_count: Option<usize>,
    pub opk_present_count: Option<usize>,
    pub opk_consumed_count: Option<usize>,
    pub pre_key_bundle_fetch_bytes: Option<usize>,
    pub prekey_message_count: Option<usize>,
    pub whisper_message_count: Option<usize>,
    pub ratchet_message_counter: Option<u32>,
    pub out_of_order_messages_seen: Option<usize>,
    pub duplicate_messages_seen: Option<usize>,
    pub skipped_keys_buffered: Option<usize>,

    pub participant_count: Option<usize>,
    pub new_participant_count: Option<usize>,
    pub ciphersuite: Option<String>,
    pub payload_class: Option<String>,

    pub app_msg_plaintext_bytes: Option<usize>,
    pub app_msg_padding_bytes: Option<usize>,
    pub app_msg_ciphertext_bytes: Option<usize>,
    pub aad_bytes: Option<usize>,

    pub pid: u32,
    pub thread_id: String,

    pub run_id: Option<String>,
    pub scenario: Option<String>,
    pub node_name: Option<String>,
    pub pod_name: Option<String>,
}

pub fn emit_event(event: &ProfileEvent) {
    let Some(lock) = writer().as_ref() else {
        return;
    };

    let Ok(mut guard) = lock.lock() else {
        return;
    };

    if let Ok(line) = serde_json::to_string(event) {
        let _ = guard.write_all(line.as_bytes());
        let _ = guard.write_all(b"\n");
        let _ = guard.flush();
    }
}

pub struct ProfileScope {
    op: String,
    implementation: String,
    wall_start: Instant,
    cpu_start: Option<ThreadTime>,
}

impl ProfileScope {
    pub fn start(op: impl Into<String>, implementation: impl Into<String>) -> Option<Self> {
        if !profiling_enabled() {
            return None;
        }

        Some(Self {
            op: op.into(),
            implementation: implementation.into(),
            wall_start: Instant::now(),
            cpu_start: Some(ThreadTime::now()),
        })
    }

    pub fn finish(self) -> ProfileEvent {
        ProfileEvent {
            ts_unix_ns: unix_timestamp_ns(),
            op: self.op,
            implementation: self.implementation,

            wall_ns: self.wall_start.elapsed().as_nanos(),
            cpu_thread_ns: self.cpu_start.map(|start| start.elapsed().as_nanos()),

            alloc_bytes: None,
            alloc_count: None,

            success: true,
            protocol_bytes: None,
            wire_bytes: None,
            harness_metadata_bytes: None,
            ciphertext_count: None,
            recipient_count: None,
            fanout_recipients: None,
            session_setup_count: None,
            opk_present_count: None,
            opk_consumed_count: None,
            pre_key_bundle_fetch_bytes: None,
            prekey_message_count: None,
            whisper_message_count: None,
            ratchet_message_counter: None,
            out_of_order_messages_seen: None,
            duplicate_messages_seen: None,
            skipped_keys_buffered: None,

            participant_count: None,
            new_participant_count: None,
            ciphersuite: None,
            payload_class: None,

            app_msg_plaintext_bytes: None,
            app_msg_padding_bytes: None,
            app_msg_ciphertext_bytes: None,
            aad_bytes: None,

            pid: std::process::id(),
            thread_id: format!("{:?}", std::thread::current().id()),

            run_id: env_or_none("SIGNAL_PROFILE_RUN_ID"),
            scenario: env_or_none("SIGNAL_PROFILE_SCENARIO"),
            node_name: env_or_none("SIGNAL_PROFILE_NODE"),
            pod_name: env_or_none("SIGNAL_PROFILE_POD"),
        }
    }
}

pub fn finish_and_emit(scope: Option<ProfileScope>, fill: impl FnOnce(&mut ProfileEvent)) {
    let Some(scope) = scope else {
        return;
    };

    let mut event = scope.finish();
    fill(&mut event);
    emit_event(&event);
}
