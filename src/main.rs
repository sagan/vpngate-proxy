mod config;
mod process;
mod routing;
mod vpngate;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use config::Config;
use process::{run_vpn_loop, sleep_interruptible, spawn_vproxy_supervisor};
use routing::setup_policy_routing;
use vpngate::{build_http_agent, fetch_global_ip};

fn main() {
    let config = Config::from_env();
    println!("VPNGATE_PROXY_COUNTRY={}", config.country);

    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(err) = signal_hook::flag::register(sig, Arc::clone(&shutdown)) {
            eprintln!("Warning: failed to register signal handler for {sig}: {err}");
        }
    }

    setup_policy_routing();

    let agent = build_http_agent(config.http_timeout);

    let before_ip = loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        match fetch_global_ip(&agent, &config.ip_check_url) {
            Ok(ip) => break ip,
            Err(err) => {
                eprintln!("Failed to determine initial global IP: {err}; retrying in 5s");
                if !sleep_interruptible(Duration::from_secs(5), &shutdown) {
                    return;
                }
            }
        }
    };
    println!("Initial global IP: {before_ip}");

    let mut proxy_handles = Vec::new();
    proxy_handles.push(spawn_vproxy_supervisor(
        "vproxy-auto",
        config.proxy_bind.clone(),
        "auto",
        Arc::clone(&shutdown),
    ));

    if config.enable_udp {
        if !sleep_interruptible(Duration::from_secs(1), &shutdown) {
            for handle in proxy_handles {
                let _ = handle.join();
            }
            return;
        }
        proxy_handles.push(spawn_vproxy_supervisor(
            "vproxy-quic",
            config.proxy_bind.clone(),
            "quic",
            Arc::clone(&shutdown),
        ));
    }

    run_vpn_loop(&config, &agent, &before_ip, &shutdown);

    println!("Shutting down...");
    shutdown.store(true, Ordering::Relaxed);
    for handle in proxy_handles {
        let _ = handle.join();
    }
}
