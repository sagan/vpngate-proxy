use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::vpngate::{VpnServer, fetch_global_ip, fetch_servers};

pub struct ManagedChild {
    name: String,
    child: Child,
}

impl ManagedChild {
    pub fn spawn(name: impl Into<String>, program: &str, args: &[&str]) -> Result<Self, String> {
        let name = name.into();
        let child = Command::new(program)
            .args(args)
            .spawn()
            .map_err(|e| format!("failed to spawn {name} ({program}): {e}"))?;
        Ok(Self { name, child })
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        self.child
            .try_wait()
            .map_err(|e| format!("failed to poll {}: {e}", self.name))
    }

    pub fn terminate(&mut self, grace: Duration) {
        let pid = self.child.id() as libc::pid_t;
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }

        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }

        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(_) => break,
            }
        }

        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.terminate(Duration::from_secs(3));
    }
}

pub fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        let step = (deadline - now).min(Duration::from_millis(250));
        thread::sleep(step);
    }
    false
}

pub fn spawn_vproxy_supervisor(
    name: &'static str,
    bind: String,
    mode: &'static str,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            println!("Starting {name} (vproxy run --bind {bind} {mode})");
            match ManagedChild::spawn(name, "vproxy", &["run", "--bind", &bind, mode]) {
                Ok(mut proc) => {
                    while !shutdown.load(Ordering::Relaxed) {
                        match proc.try_wait() {
                            Ok(Some(status)) => {
                                eprintln!("{name} exited unexpectedly with {status}");
                                break;
                            }
                            Ok(None) => thread::sleep(Duration::from_millis(500)),
                            Err(err) => {
                                eprintln!("{name} wait error: {err}");
                                break;
                            }
                        }
                    }
                    if shutdown.load(Ordering::Relaxed) {
                        proc.terminate(Duration::from_secs(5));
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("{err}");
                }
            }
            if !sleep_interruptible(Duration::from_secs(2), &shutdown) {
                break;
            }
        }
    })
}

fn write_ovpn_config(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    file.write_all(data)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn run_vpn_loop(
    config: &Config,
    agent: &ureq::Agent,
    before_ip: &str,
    shutdown: &AtomicBool,
) {
    let ovpn_path = PathBuf::from("/tmp/vpngate-active.ovpn");

    while !shutdown.load(Ordering::Relaxed) {
        println!("Fetching VPNGate server list for country={}...", config.country);
        let servers = match fetch_servers(agent, &config.vpngate_url, &config.country) {
            Ok(list) if !list.is_empty() => list,
            Ok(_) => {
                eprintln!(
                    "No VPNGate servers found for country={}, retrying in 10s",
                    config.country
                );
                sleep_interruptible(Duration::from_secs(10), shutdown);
                continue;
            }
            Err(err) => {
                eprintln!("Failed to fetch VPNGate server list: {err}; retrying in 10s");
                sleep_interruptible(Duration::from_secs(10), shutdown);
                continue;
            }
        };

        println!("Found {} candidate servers", servers.len());

        for server in &servers {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            run_single_server(config, agent, before_ip, server, &ovpn_path, shutdown);
        }

        if !shutdown.load(Ordering::Relaxed) {
            println!("Exhausted server list, refreshing...");
            sleep_interruptible(Duration::from_secs(3), shutdown);
        }
    }
}

fn run_single_server(
    config: &Config,
    agent: &ureq::Agent,
    before_ip: &str,
    server: &VpnServer,
    ovpn_path: &Path,
    shutdown: &AtomicBool,
) {
    if let Err(err) = write_ovpn_config(ovpn_path, &server.ovpn_config) {
        eprintln!("{err}");
        return;
    }
    let _guard = TempFileGuard(ovpn_path.to_path_buf());

    println!(
        "Connecting to {} ({}, {})",
        server.host_name, server.ip, server.country_short
    );

    let path_str = ovpn_path.to_string_lossy();
    let mut vpn = match ManagedChild::spawn("openvpn", "openvpn", &["--config", &path_str]) {
        Ok(child) => child,
        Err(err) => {
            eprintln!("{err}");
            return;
        }
    };

    // Wait for OpenVPN to establish tunnel (up to vpn_startup_timeout).
    let startup_deadline = Instant::now() + config.vpn_startup_timeout;
    let mut connected = false;

    while !shutdown.load(Ordering::Relaxed) && Instant::now() < startup_deadline {
        if !sleep_interruptible(config.vpn_poll_interval, shutdown) {
            break;
        }
        match vpn.try_wait() {
            Ok(Some(status)) => {
                eprintln!("openvpn exited during startup with {status}");
                return;
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("{err}");
                return;
            }
        }

        match fetch_global_ip(agent, &config.ip_check_url) {
            Ok(after_ip) => {
                println!("before={before_ip} after={after_ip}");
                if after_ip != before_ip {
                    connected = true;
                    break;
                }
            }
            Err(err) => {
                eprintln!("IP check during startup failed: {err}");
            }
        }
    }

    if shutdown.load(Ordering::Relaxed) {
        vpn.terminate(Duration::from_secs(5));
        return;
    }

    if !connected {
        eprintln!(
            "VPN did not change global IP within {:?}, disconnecting {}",
            config.vpn_startup_timeout, server.host_name
        );
        vpn.terminate(Duration::from_secs(5));
        return;
    }

    // Connected: monitor periodically until shutdown, process exit, or IP leak/failure.
    let mut consecutive_failures = 0u32;
    while !shutdown.load(Ordering::Relaxed) {
        if !sleep_interruptible(config.vpn_check_interval, shutdown) {
            break;
        }
        match vpn.try_wait() {
            Ok(Some(status)) => {
                eprintln!("openvpn exited with {status}");
                return;
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("{err}");
                break;
            }
        }

        match fetch_global_ip(agent, &config.ip_check_url) {
            Ok(after_ip) => {
                println!("before={before_ip} after={after_ip}");
                if after_ip == before_ip {
                    eprintln!("Global IP reverted to {before_ip}, reconnecting...");
                    break;
                }
                consecutive_failures = 0;
            }
            Err(err) => {
                consecutive_failures += 1;
                eprintln!("IP health check failed ({consecutive_failures}/2): {err}");
                if consecutive_failures >= 2 {
                    eprintln!("Too many consecutive IP check failures, reconnecting...");
                    break;
                }
            }
        }
    }

    vpn.terminate(Duration::from_secs(5));
}
