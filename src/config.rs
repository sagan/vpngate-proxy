use std::env;
use std::time::Duration;

pub const DEFAULT_VPNGATE_URL: &str = "http://www.vpngate.net/api/iphone/";
pub const DEFAULT_IP_CHECK_URL: &str = "http://inet-ip.info";
pub const DEFAULT_PROXY_BIND: &str = "0.0.0.0:8118";

#[derive(Debug, Clone)]
pub struct Config {
    pub country: String,
    pub enable_udp: bool,
    pub vpngate_url: String,
    pub ip_check_url: String,
    pub proxy_bind: String,
    pub http_timeout: Duration,
    pub vpn_startup_timeout: Duration,
    pub vpn_check_interval: Duration,
    pub vpn_poll_interval: Duration,
    pub failed_server_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Self {
        let country = env::var("VPNGATE_PROXY_COUNTRY")
            .ok()
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "JP".to_string());

        let enable_udp = env::var("VPNGATE_PROXY_UDP")
            .map(|v| v.trim() == "1")
            .unwrap_or(false);

        Self {
            country,
            enable_udp,
            vpngate_url: DEFAULT_VPNGATE_URL.to_string(),
            ip_check_url: DEFAULT_IP_CHECK_URL.to_string(),
            proxy_bind: DEFAULT_PROXY_BIND.to_string(),
            http_timeout: Duration::from_secs(15),
            vpn_startup_timeout: Duration::from_secs(30),
            vpn_check_interval: Duration::from_secs(60),
            vpn_poll_interval: Duration::from_secs(5),
            failed_server_ttl: Duration::from_secs(15 * 60),
        }
    }
}
