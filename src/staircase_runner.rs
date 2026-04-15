use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::worker_api::{Command, CommandResponse};

#[derive(Debug, Clone)]
pub struct StaircaseConfig {
    pub key_repository_url: String,
    pub workers: Vec<WorkerSpec>,
    pub min_size: usize,
    pub max_size: Option<usize>,
    pub step_size: usize,
    pub roundtrips: usize,
    pub update_rounds: usize,
    pub app_rounds: usize,
    pub max_update_samples_per_plateau: usize,
    pub max_app_samples_per_payload: usize,
    pub payload_sizes: Vec<usize>,
    pub run_id: String,
    pub scenario: String,
    pub output_dir: String,
}

#[derive(Debug, Clone)]
pub struct WorkerSpec {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProfileEvent {
    ts_unix_ns: u128,
    op: String,
    implementation: String,
    wall_ns: u128,
    cpu_thread_ns: Option<u128>,
    alloc_bytes: Option<u64>,
    alloc_count: Option<u64>,
    success: bool,
    protocol_bytes: Option<usize>,
    wire_bytes: Option<usize>,
    harness_metadata_bytes: Option<usize>,
    ciphertext_count: Option<usize>,
    recipient_count: Option<usize>,
    fanout_recipients: Option<usize>,
    session_setup_count: Option<usize>,
    opk_present_count: Option<usize>,
    opk_consumed_count: Option<usize>,
    pre_key_bundle_fetch_bytes: Option<usize>,
    prekey_message_count: Option<usize>,
    whisper_message_count: Option<usize>,
    ratchet_message_counter: Option<u32>,
    out_of_order_messages_seen: Option<usize>,
    duplicate_messages_seen: Option<usize>,
    skipped_keys_buffered: Option<usize>,
    participant_count: Option<usize>,
    new_participant_count: Option<usize>,
    ciphersuite: Option<String>,
    payload_class: Option<String>,
    app_msg_plaintext_bytes: Option<usize>,
    app_msg_padding_bytes: Option<usize>,
    app_msg_ciphertext_bytes: Option<usize>,
    aad_bytes: Option<usize>,
    pid: u32,
    thread_id: String,
    run_id: Option<String>,
    scenario: Option<String>,
    node_name: Option<String>,
    pod_name: Option<String>,
}

struct Progress {
    total_units: usize,
    completed_units: usize,
    start: Instant,
}

impl Progress {
    fn new(total_units: usize) -> Self {
        Self {
            total_units: total_units.max(1),
            completed_units: 0,
            start: Instant::now(),
        }
    }

    fn tick(&mut self, label: &str) {
        self.completed_units = (self.completed_units + 1).min(self.total_units);
        self.render(label);
    }

    fn render(&self, label: &str) {
        let width = 32usize;
        let ratio = self.completed_units as f64 / self.total_units as f64;
        let filled = ((ratio * width as f64).round() as usize).min(width);

        let mut bar = String::with_capacity(width);
        for _ in 0..filled {
            bar.push('#');
        }
        for _ in filled..width {
            bar.push('-');
        }

        let elapsed = self.start.elapsed();
        let eta = if self.completed_units == 0 {
            None
        } else {
            let elapsed_secs = elapsed.as_secs_f64();
            let per_unit = elapsed_secs / self.completed_units as f64;
            let remaining = self.total_units.saturating_sub(self.completed_units) as f64;
            Some(Duration::from_secs_f64(per_unit * remaining))
        };

        let percent = ratio * 100.0;
        let eta_text = eta
            .map(format_hms)
            .unwrap_or_else(|| "--:--:--".to_string());

        eprint!(
            "\r[{}] {:6.2}% | {}/{} units | elapsed {} | ETA {} | {}",
            bar,
            percent,
            self.completed_units,
            self.total_units,
            format_hms(elapsed),
            eta_text,
            label
        );
        let _ = io::stderr().flush();
    }

    fn finish(&self) {
        eprintln!();
    }
}

pub fn parse_worker_specs(raw_specs: &[String]) -> Result<Vec<WorkerSpec>> {
    let mut workers = Vec::with_capacity(raw_specs.len());

    for raw in raw_specs {
        let spec = parse_worker_spec(raw)?;
        if workers.iter().any(|w: &WorkerSpec| w.id == spec.id) {
            return Err(anyhow!("Duplicate worker id '{}'", spec.id));
        }
        workers.push(spec);
    }

    if workers.is_empty() {
        return Err(anyhow!("At least one worker must be provided"));
    }

    Ok(workers)
}

pub fn run_dir_for(output_dir: &str, run_id: &str) -> PathBuf {
    PathBuf::from(output_dir).join(run_id)
}

pub fn run_staircase_benchmark(config: StaircaseConfig) -> Result<()> {
    let max_size = validate_config(&config, config.workers.len())?;

    let run_dir = run_dir_for(&config.output_dir, &config.run_id);
    fs::create_dir_all(&run_dir)?;

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")?;

    wait_for_health(&http, &config.key_repository_url, Duration::from_secs(10)).with_context(
        || {
            format!(
                "Key repository at {} is not healthy",
                config.key_repository_url
            )
        },
    )?;

    for worker in &config.workers {
        wait_for_health(&http, &worker.url, Duration::from_secs(10))
            .with_context(|| format!("Worker {} at {} is not healthy", worker.id, worker.url))?;
    }

    let plateau_sequence = build_plateau_sequence(
        config.min_size,
        max_size,
        config.step_size,
        config.roundtrips,
    );

    let total_units = estimate_total_units(
        &plateau_sequence,
        config.workers.len(),
        config.update_rounds,
        config.app_rounds,
        config.max_update_samples_per_plateau,
        config.max_app_samples_per_payload,
        config.payload_sizes.len(),
    );

    eprintln!(
        "Scenario plan: plateaus={:?}, payload_sizes={:?}, shared_protocol_updates=disabled, app_cap={}, total_units≈{}",
        plateau_sequence,
        config.payload_sizes,
        config.max_app_samples_per_payload,
        total_units
    );

    let mut progress = Progress::new(total_units);
    progress.render("starting");

    publish_pre_key_bundles(&http, &config.workers, &mut progress)?;

    // The active set is runner-owned benchmark metadata, not shared protocol state.
    let mut active = Vec::new();
    let mut idle: VecDeque<WorkerSpec> = config.workers.iter().cloned().collect();

    for (plateau_idx, &target_size) in plateau_sequence.iter().enumerate() {
        eprintln!(
            "\n=== Plateau {}/{} | target active members = {} ===",
            plateau_idx + 1,
            plateau_sequence.len(),
            target_size
        );

        transition_to_size(&mut active, &mut idle, target_size, &mut progress)?;

        let active_ids: Vec<String> = active.iter().map(|w| w.id.clone()).collect();
        eprintln!(
            "\n[plateau {}] active benchmark participants {:?}",
            target_size, active_ids
        );

        run_update_phase(
            target_size,
            config.update_rounds,
            config.max_update_samples_per_plateau,
        )?;

        run_application_phase(
            &http,
            &active,
            target_size,
            config.app_rounds,
            config.max_app_samples_per_payload,
            &config.payload_sizes,
            &mut progress,
        )?;

        eprintln!("\n=== Plateau {} complete ===", target_size);
    }

    progress.finish();

    let worker_ids: Vec<String> = config.workers.iter().map(|w| w.id.clone()).collect();
    aggregate_csv(&run_dir, &worker_ids)?;

    println!(
        "HTTP staircase benchmark finished. Output in {}",
        run_dir.display()
    );
    Ok(())
}

fn format_hms(d: Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn parse_worker_spec(raw: &str) -> Result<WorkerSpec> {
    let (id, url) = raw
        .split_once('=')
        .ok_or_else(|| anyhow!("Invalid worker '{}', expected ID=URL", raw))?;

    let id = id.trim();
    let url = url.trim().trim_end_matches('/');

    if id.is_empty() {
        return Err(anyhow!("Worker id cannot be empty in '{}'", raw));
    }
    if url.is_empty() {
        return Err(anyhow!("Worker url cannot be empty in '{}'", raw));
    }

    Ok(WorkerSpec {
        id: id.to_string(),
        url: url.to_string(),
    })
}

fn wait_for_health(
    http: &reqwest::blocking::Client,
    base_url: &str,
    timeout: Duration,
) -> Result<()> {
    let url = format!("{}/health", base_url.trim_end_matches('/'));
    let start = Instant::now();

    while start.elapsed() < timeout {
        match http.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(250)),
        }
    }

    Err(anyhow!("Timeout waiting for health endpoint at {}", url))
}

fn send_command(
    http: &reqwest::blocking::Client,
    worker: &WorkerSpec,
    command: &Command,
) -> Result<CommandResponse> {
    let url = format!("{}/command", worker.url);

    let response = http
        .post(&url)
        .json(command)
        .send()
        .with_context(|| format!("Failed to POST command to worker {}", worker.id))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "Worker {} returned HTTP {}: {}",
            worker.id,
            status,
            body
        ));
    }

    let parsed: CommandResponse = response
        .json()
        .with_context(|| format!("Failed to decode JSON response from worker {}", worker.id))?;

    Ok(parsed)
}

fn send_cmd_expect_ok_fragment(
    http: &reqwest::blocking::Client,
    worker: &WorkerSpec,
    command: &Command,
    ok_fragment: &str,
) -> Result<String> {
    let response = send_command(http, worker, command)?;

    match response.status.as_str() {
        "ok" if response.message.contains(ok_fragment) => Ok(response.message),
        "ok" => Err(anyhow!(
            "Worker {} returned unexpected ok message: {}",
            worker.id,
            response.message
        )),
        "error" => Err(anyhow!("Worker {} error: {}", worker.id, response.message)),
        other => Err(anyhow!(
            "Worker {} returned unknown status '{}': {}",
            worker.id,
            other,
            response.message
        )),
    }
}

fn stepped_sizes(min_size: usize, max_size: usize, step_size: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut current = min_size;

    sizes.push(current);
    while current < max_size {
        let next = current.saturating_add(step_size);
        current = next.min(max_size);
        if sizes.last().copied() != Some(current) {
            sizes.push(current);
        }
    }

    sizes
}

fn build_plateau_sequence(
    min_size: usize,
    max_size: usize,
    step_size: usize,
    roundtrips: usize,
) -> Vec<usize> {
    let ascent = stepped_sizes(min_size, max_size, step_size);
    let mut sequence = Vec::new();

    for _ in 0..roundtrips {
        for &size in &ascent {
            if sequence.last().copied() != Some(size) {
                sequence.push(size);
            }
        }
        for &size in ascent.iter().rev().skip(1) {
            if sequence.last().copied() != Some(size) {
                sequence.push(size);
            }
        }
    }

    sequence
}

fn cap_count(raw: usize, cap: usize) -> usize {
    if cap == 0 {
        0
    } else {
        raw.min(cap)
    }
}

fn update_ops_for_plateau(
    _size: usize,
    _update_rounds: usize,
    _max_update_samples_per_plateau: usize,
) -> usize {
    0
}

fn app_sends_per_payload_for_plateau(
    size: usize,
    app_rounds: usize,
    max_app_samples_per_payload: usize,
) -> usize {
    if size < 2 {
        0
    } else {
        cap_count(app_rounds.saturating_mul(size), max_app_samples_per_payload)
    }
}

fn app_ops_for_plateau(
    size: usize,
    app_rounds: usize,
    max_app_samples_per_payload: usize,
    payload_count: usize,
) -> usize {
    app_sends_per_payload_for_plateau(size, app_rounds, max_app_samples_per_payload)
        .saturating_mul(payload_count)
}

fn estimate_total_units(
    plateau_sequence: &[usize],
    worker_count: usize,
    update_rounds: usize,
    app_rounds: usize,
    max_update_samples_per_plateau: usize,
    max_app_samples_per_payload: usize,
    payload_count: usize,
) -> usize {
    let mut total = worker_count;
    let mut current_size = 0usize;

    for &target in plateau_sequence {
        total = total.saturating_add(target.abs_diff(current_size));
        total = total.saturating_add(update_ops_for_plateau(
            target,
            update_rounds,
            max_update_samples_per_plateau,
        ));
        total = total.saturating_add(app_ops_for_plateau(
            target,
            app_rounds,
            max_app_samples_per_payload,
            payload_count,
        ));
        current_size = target;
    }

    total
}

fn deterministic_payload(
    len: usize,
    plateau_size: usize,
    payload_size: usize,
    seq_no: usize,
    actor_id: &str,
) -> String {
    if len == 0 {
        return String::new();
    }

    let seed = format!(
        "plateau={};payload={};seq={};actor={};",
        plateau_size, payload_size, seq_no, actor_id
    );

    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.push_str(&seed);
    }
    out.truncate(len);
    out
}

fn publish_pre_key_bundles(
    http: &reqwest::blocking::Client,
    workers: &[WorkerSpec],
    progress: &mut Progress,
) -> Result<()> {
    for worker in workers {
        let fragment = format!("pre-key bundle uploaded for {}", worker.id);
        send_cmd_expect_ok_fragment(http, worker, &Command::GeneratePreKeyBundle, &fragment)?;
        progress.tick(&format!("publish pre-key bundle {}", worker.id));
    }

    Ok(())
}

fn activate_one_participant(
    active: &mut Vec<WorkerSpec>,
    idle: &mut VecDeque<WorkerSpec>,
    progress: &mut Progress,
) -> Result<()> {
    let joiner = idle
        .pop_front()
        .ok_or_else(|| anyhow!("No idle worker available to add"))?;

    active.push(joiner.clone());
    progress.tick(&format!("activate {}", joiner.id));
    Ok(())
}

fn deactivate_one_participant(
    active: &mut Vec<WorkerSpec>,
    idle: &mut VecDeque<WorkerSpec>,
    progress: &mut Progress,
) -> Result<()> {
    if active.is_empty() {
        return Err(anyhow!("No active worker available to deactivate"));
    }

    let actually_removed = active
        .pop()
        .ok_or_else(|| anyhow!("Active set unexpectedly empty during removal"))?;
    idle.push_front(actually_removed.clone());

    progress.tick(&format!("deactivate {}", actually_removed.id));
    Ok(())
}

fn transition_to_size(
    active: &mut Vec<WorkerSpec>,
    idle: &mut VecDeque<WorkerSpec>,
    target_size: usize,
    progress: &mut Progress,
) -> Result<()> {
    while active.len() < target_size {
        activate_one_participant(active, idle, progress)?;
    }

    while active.len() > target_size {
        deactivate_one_participant(active, idle, progress)?;
    }

    Ok(())
}

fn run_update_phase(
    plateau_size: usize,
    update_rounds: usize,
    max_update_samples_per_plateau: usize,
) -> Result<()> {
    let total_updates =
        update_ops_for_plateau(plateau_size, update_rounds, max_update_samples_per_plateau);
    if total_updates == 0 {
        if update_rounds > 0 && max_update_samples_per_plateau > 0 {
            eprintln!(
                "\n[plateau {}] shared protocol update phase skipped: vanilla Signal has no group epoch/commit step",
                plateau_size
            );
        }
        return Ok(());
    }

    Ok(())
}

fn run_application_phase(
    http: &reqwest::blocking::Client,
    active: &[WorkerSpec],
    plateau_size: usize,
    app_rounds: usize,
    max_app_samples_per_payload: usize,
    payload_sizes: &[usize],
    progress: &mut Progress,
) -> Result<()> {
    if active.len() < 2 {
        eprintln!(
            "\n[plateau {}] application phase skipped: fewer than 2 active members",
            plateau_size
        );
        return Ok(());
    }

    let per_payload_count =
        app_sends_per_payload_for_plateau(plateau_size, app_rounds, max_app_samples_per_payload);
    if per_payload_count == 0 {
        return Ok(());
    }

    for &payload_size in payload_sizes {
        eprintln!(
            "\n[plateau {}] application phase: {} successful sends at payload {} B",
            plateau_size, per_payload_count, payload_size
        );

        for seq_no in 0..per_payload_count {
            let actor_idx = seq_no % active.len();
            let actor = &active[actor_idx];
            let payload =
                deterministic_payload(payload_size, plateau_size, payload_size, seq_no, &actor.id);
            let recipients: Vec<&WorkerSpec> = active
                .iter()
                .enumerate()
                .filter_map(|(idx, worker)| (idx != actor_idx).then_some(worker))
                .collect();
            let recipient_ids: Vec<String> =
                recipients.iter().map(|worker| worker.id.clone()).collect();

            let send_message = send_cmd_expect_ok_fragment(
                http,
                actor,
                &Command::SendFanoutMessage {
                    recipients: recipient_ids.clone(),
                    message: payload.clone(),
                },
                "fanout message sent to",
            )?;
            let expected_send_message =
                format!("fanout message sent to {} recipients", recipient_ids.len());
            if send_message != expected_send_message {
                return Err(anyhow!(
                    "Worker {} returned unexpected send confirmation: {}",
                    actor.id,
                    send_message
                ));
            }

            for recipient_id in &recipient_ids {
                let session_message = send_cmd_expect_ok_fragment(
                    http,
                    actor,
                    &Command::SessionExists {
                        peer: recipient_id.clone(),
                    },
                    "session_exists",
                )?;
                let expected_session_message =
                    format!("session_exists peer={} value=true", recipient_id);
                if session_message != expected_session_message {
                    return Err(anyhow!(
                        "Worker {} session check failed after send: {}",
                        actor.id,
                        session_message
                    ));
                }
            }

            let sampled_pos = seq_no % recipients.len();

            for (pos, worker) in recipients.iter().enumerate() {
                let profile = pos == sampled_pos;

                let receive_message = send_cmd_expect_ok_fragment(
                    http,
                    worker,
                    &Command::ReceivePairwiseMessage { profile },
                    "pairwise message received:",
                )?;
                let expected_receive_message = format!("pairwise message received: {}", payload);
                if receive_message != expected_receive_message {
                    return Err(anyhow!(
                        "Worker {} decrypted unexpected plaintext: {}",
                        worker.id,
                        receive_message
                    ));
                }

                let session_message = send_cmd_expect_ok_fragment(
                    http,
                    worker,
                    &Command::SessionExists {
                        peer: actor.id.clone(),
                    },
                    "session_exists",
                )?;
                let expected_session_message =
                    format!("session_exists peer={} value=true", actor.id);
                if session_message != expected_session_message {
                    return Err(anyhow!(
                        "Worker {} session check failed after receive: {}",
                        worker.id,
                        session_message
                    ));
                }
            }

            progress.tick(&format!(
                "plateau {} app payload={} {}/{} actor={}",
                plateau_size,
                payload_size,
                seq_no + 1,
                per_payload_count,
                actor.id
            ));
        }
    }

    Ok(())
}

fn aggregate_csv(run_dir: &Path, worker_ids: &[String]) -> Result<()> {
    let csv_path = run_dir.join("events.csv");
    let mut wtr = csv::Writer::from_path(&csv_path)?;

    #[derive(Serialize)]
    struct CsvRow<'a> {
        worker_id: &'a str,
        ts_unix_ns: u128,
        op: String,
        implementation: String,
        wall_ns: u128,
        cpu_thread_ns: Option<u128>,
        alloc_bytes: Option<u64>,
        alloc_count: Option<u64>,
        success: bool,
        protocol_bytes: Option<usize>,
        wire_bytes: Option<usize>,
        harness_metadata_bytes: Option<usize>,
        ciphertext_count: Option<usize>,
        recipient_count: Option<usize>,
        fanout_recipients: Option<usize>,
        session_setup_count: Option<usize>,
        opk_present_count: Option<usize>,
        opk_consumed_count: Option<usize>,
        pre_key_bundle_fetch_bytes: Option<usize>,
        prekey_message_count: Option<usize>,
        whisper_message_count: Option<usize>,
        ratchet_message_counter: Option<u32>,
        out_of_order_messages_seen: Option<usize>,
        duplicate_messages_seen: Option<usize>,
        skipped_keys_buffered: Option<usize>,
        participant_count: Option<usize>,
        new_participant_count: Option<usize>,
        ciphersuite: Option<String>,
        payload_class: Option<String>,
        app_msg_plaintext_bytes: Option<usize>,
        app_msg_padding_bytes: Option<usize>,
        app_msg_ciphertext_bytes: Option<usize>,
        aad_bytes: Option<usize>,
        pid: u32,
        thread_id: String,
        run_id: Option<String>,
        scenario: Option<String>,
        node_name: Option<String>,
        pod_name: Option<String>,
    }

    for worker_id in worker_ids {
        let path = run_dir.join(format!("client-{worker_id}.jsonl"));
        if !path.exists() {
            continue;
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let event: ProfileEvent = serde_json::from_str(&line)
                .with_context(|| format!("Invalid json in {}", path.display()))?;

            let row = CsvRow {
                worker_id,
                ts_unix_ns: event.ts_unix_ns,
                op: event.op,
                implementation: event.implementation,
                wall_ns: event.wall_ns,
                cpu_thread_ns: event.cpu_thread_ns,
                alloc_bytes: event.alloc_bytes,
                alloc_count: event.alloc_count,
                success: event.success,
                protocol_bytes: event.protocol_bytes,
                wire_bytes: event.wire_bytes,
                harness_metadata_bytes: event.harness_metadata_bytes,
                ciphertext_count: event.ciphertext_count,
                recipient_count: event.recipient_count,
                fanout_recipients: event.fanout_recipients,
                session_setup_count: event.session_setup_count,
                opk_present_count: event.opk_present_count,
                opk_consumed_count: event.opk_consumed_count,
                pre_key_bundle_fetch_bytes: event.pre_key_bundle_fetch_bytes,
                prekey_message_count: event.prekey_message_count,
                whisper_message_count: event.whisper_message_count,
                ratchet_message_counter: event.ratchet_message_counter,
                out_of_order_messages_seen: event.out_of_order_messages_seen,
                duplicate_messages_seen: event.duplicate_messages_seen,
                skipped_keys_buffered: event.skipped_keys_buffered,
                participant_count: event.participant_count,
                new_participant_count: event.new_participant_count,
                ciphersuite: event.ciphersuite,
                payload_class: event.payload_class,
                app_msg_plaintext_bytes: event.app_msg_plaintext_bytes,
                app_msg_padding_bytes: event.app_msg_padding_bytes,
                app_msg_ciphertext_bytes: event.app_msg_ciphertext_bytes,
                aad_bytes: event.aad_bytes,
                pid: event.pid,
                thread_id: event.thread_id,
                run_id: event.run_id,
                scenario: event.scenario,
                node_name: event.node_name,
                pod_name: event.pod_name,
            };

            wtr.serialize(row)?;
        }
    }

    wtr.flush()?;
    eprintln!(
        "CSV columns: worker_id, ts_unix_ns, op, implementation, wall_ns, cpu_thread_ns, alloc_bytes, alloc_count, success, protocol_bytes, wire_bytes, harness_metadata_bytes, ciphertext_count, recipient_count, fanout_recipients, session_setup_count, opk_present_count, opk_consumed_count, pre_key_bundle_fetch_bytes, prekey_message_count, whisper_message_count, ratchet_message_counter, out_of_order_messages_seen, duplicate_messages_seen, skipped_keys_buffered, participant_count, new_participant_count, ciphersuite, payload_class, app_msg_plaintext_bytes, app_msg_padding_bytes, app_msg_ciphertext_bytes, aad_bytes, pid, thread_id, run_id, scenario, node_name, pod_name"
    );
    Ok(())
}

fn validate_config(config: &StaircaseConfig, worker_count: usize) -> Result<usize> {
    if config.min_size == 0 {
        return Err(anyhow!("--min-size must be at least 1"));
    }
    if config.step_size == 0 {
        return Err(anyhow!("--step-size must be at least 1"));
    }
    if config.roundtrips == 0 {
        return Err(anyhow!("--roundtrips must be at least 1"));
    }
    if config.payload_sizes.is_empty() {
        return Err(anyhow!("At least one payload size is required"));
    }

    let max_size = config.max_size.unwrap_or(worker_count);

    if max_size == 0 {
        return Err(anyhow!("--max-size must be at least 1"));
    }
    if max_size > worker_count {
        return Err(anyhow!(
            "--max-size {} exceeds number of supplied workers {}",
            max_size,
            worker_count
        ));
    }
    if config.min_size > max_size {
        return Err(anyhow!(
            "--min-size {} cannot exceed --max-size {}",
            config.min_size,
            max_size
        ));
    }

    Ok(max_size)
}
