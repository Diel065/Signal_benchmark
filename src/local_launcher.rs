use std::{
    fs::{self, File},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{anyhow, Context, Result};

use crate::staircase_runner::{run_dir_for, WorkerSpec};

#[derive(Debug, Clone)]
pub struct LocalLaunchConfig {
    pub worker_count: usize,
    pub key_repository_listen_addr: SocketAddr,
    pub worker_host: String,
    pub base_worker_port: u16,
    pub run_id: String,
    pub scenario: String,
    pub output_dir: String,
}

pub struct LocalDeployment {
    pub key_repository_url: String,
    pub relay_url: String,
    pub workers: Vec<WorkerSpec>,
    key_repository_child: Option<Child>,
    relay_child: Option<Child>,
    worker_children: Vec<Child>,
}

impl Drop for LocalDeployment {
    fn drop(&mut self) {
        if let Some(child) = self.key_repository_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }

        if let Some(child) = self.relay_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }

        for child in &mut self.worker_children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn launch_local_stack(config: &LocalLaunchConfig) -> Result<LocalDeployment> {
    if config.worker_count == 0 {
        return Err(anyhow!("--spawn-local-workers must be at least 1"));
    }

    let run_dir = run_dir_for(&config.output_dir, &config.run_id);
    fs::create_dir_all(&run_dir)?;

    let bin_dir = current_bin_dir()?;
    let (key_repository_bin, relay_bin, worker_bin) = ensure_binaries_available(&bin_dir)?;

    let key_repository_url = format!("http://{}", config.key_repository_listen_addr);

    let relay_listen_addr = derive_relay_listen_addr(config.key_repository_listen_addr)?;
    let relay_url = format!("http://{}", relay_listen_addr);

    let key_repository_log_path = run_dir.join("key_repository.log");
    let key_repository_log = File::create(&key_repository_log_path)
        .with_context(|| format!("Could not create {}", key_repository_log_path.display()))?;
    let key_repository_log_err = key_repository_log.try_clone()?;

    let key_repository_child = Command::new(&key_repository_bin)
        .arg("--listen-addr")
        .arg(config.key_repository_listen_addr.to_string())
        .stdout(Stdio::from(key_repository_log))
        .stderr(Stdio::from(key_repository_log_err))
        .spawn()
        .with_context(|| {
            format!(
                "Could not spawn key repository binary at {}",
                key_repository_bin.display()
            )
        })?;

    let relay_log_path = run_dir.join("relay.log");
    let relay_log = File::create(&relay_log_path)
        .with_context(|| format!("Could not create {}", relay_log_path.display()))?;
    let relay_log_err = relay_log.try_clone()?;

    let relay_child = Command::new(&relay_bin)
        .arg("--listen-addr")
        .arg(relay_listen_addr.to_string())
        .stdout(Stdio::from(relay_log))
        .stderr(Stdio::from(relay_log_err))
        .spawn()
        .with_context(|| format!("Could not spawn relay binary at {}", relay_bin.display()))?;

    let mut workers = Vec::with_capacity(config.worker_count);
    let mut worker_children = Vec::with_capacity(config.worker_count);

    for i in 0..config.worker_count {
        let id = format!("{:05}", i + 1);

        let port = config
            .base_worker_port
            .checked_add(i as u16)
            .ok_or_else(|| anyhow!("Worker port overflow at index {}", i))?;

        let listen_addr: SocketAddr = format!("{}:{}", config.worker_host, port)
            .parse()
            .with_context(|| {
                format!(
                    "Invalid worker listen address {}:{}",
                    config.worker_host, port
                )
            })?;

        let worker_url = format!("http://{}:{}", config.worker_host, port);

        let worker_log_path = run_dir.join(format!("worker-{}.log", id));
        let worker_log = File::create(&worker_log_path)
            .with_context(|| format!("Could not create {}", worker_log_path.display()))?;
        let worker_log_err = worker_log.try_clone()?;

        let profile_path = run_dir.join(format!("client-{}.jsonl", id));

        let child = Command::new(&worker_bin)
            .arg("--name")
            .arg(&id)
            .arg("--key-repository-url")
            .arg(&key_repository_url)
            .arg("--relay-url")
            .arg(&relay_url)
            .arg("--listen-addr")
            .arg(listen_addr.to_string())
            .env("SIGNAL_PROFILE_PATH", profile_path.as_os_str())
            .env("SIGNAL_PROFILE_RUN_ID", &config.run_id)
            .env("SIGNAL_PROFILE_SCENARIO", &config.scenario)
            .stdout(Stdio::from(worker_log))
            .stderr(Stdio::from(worker_log_err))
            .spawn()
            .with_context(|| {
                format!("Could not spawn worker binary at {}", worker_bin.display())
            })?;

        workers.push(WorkerSpec {
            id,
            url: worker_url,
        });
        worker_children.push(child);
    }

    Ok(LocalDeployment {
        key_repository_url,
        relay_url,
        workers,
        key_repository_child: Some(key_repository_child),
        relay_child: Some(relay_child),
        worker_children,
    })
}

fn derive_relay_listen_addr(key_repository_listen_addr: SocketAddr) -> Result<SocketAddr> {
    let relay_port = key_repository_listen_addr
        .port()
        .checked_add(1000)
        .ok_or_else(|| {
            anyhow!(
                "Relay port overflow from key repository port {}",
                key_repository_listen_addr.port()
            )
        })?;

    Ok(SocketAddr::new(
        ip_for_relay(key_repository_listen_addr.ip()),
        relay_port,
    ))
}

fn ip_for_relay(ip: IpAddr) -> IpAddr {
    ip
}

fn current_bin_dir() -> Result<PathBuf> {
    let current_exe =
        std::env::current_exe().context("Could not determine current executable path")?;
    let bin_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("Could not determine binary directory"))?;
    Ok(bin_dir.to_path_buf())
}

fn ensure_binaries_available(bin_dir: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let key_repository_bin = bin_dir.join(executable_name("key_repository"));
    let relay_bin = bin_dir.join(executable_name("message_relay"));
    let worker_bin = bin_dir.join(executable_name("worker"));

    if key_repository_bin.exists() && relay_bin.exists() && worker_bin.exists() {
        return Ok((key_repository_bin, relay_bin, worker_bin));
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg("--bins")
        .status()
        .with_context(|| format!("Failed to invoke '{}' to build binaries", cargo))?;

    if !status.success() {
        return Err(anyhow!("'cargo build --bins' failed"));
    }

    if key_repository_bin.exists() && relay_bin.exists() && worker_bin.exists() {
        Ok((key_repository_bin, relay_bin, worker_bin))
    } else {
        Err(anyhow!(
            "Expected key repository, relay, and worker binaries at '{}', '{}', and '{}'",
            key_repository_bin.display(),
            relay_bin.display(),
            worker_bin.display()
        ))
    }
}

fn executable_name(base: &str) -> String {
    #[cfg(windows)]
    {
        format!("{base}.exe")
    }
    #[cfg(not(windows))]
    {
        base.to_string()
    }
}
