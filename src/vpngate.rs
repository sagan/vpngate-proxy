use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnServer {
    pub host_name: String,
    pub ip: String,
    pub country_short: String,
    pub ovpn_config: Vec<u8>,
}

/// Tracks recently failed VPN servers and prioritizes candidates in the same
/// subnet as the last connected server to minimize IP hopping.
pub struct ServerSelector {
    failed: HashMap<String, Instant>,
    failed_ttl: Duration,
    last_connected_ip: Option<Ipv4Addr>,
}

impl ServerSelector {
    pub fn new(failed_ttl: Duration) -> Self {
        Self {
            failed: HashMap::new(),
            failed_ttl,
            last_connected_ip: None,
        }
    }

    pub fn record_failure(&mut self, ip: &str, now: Instant) {
        self.failed.insert(ip.to_string(), now);
    }

    pub fn record_success(&mut self, ip: &str) {
        self.failed.remove(ip);
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            self.last_connected_ip = Some(parsed);
        }
    }

    pub fn clear_affinity(&mut self) {
        self.last_connected_ip = None;
    }

    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }

    pub fn prune_expired(&mut self, now: Instant) {
        self.failed
            .retain(|_, failed_at| now.saturating_duration_since(*failed_at) < self.failed_ttl);
    }

    /// Filters out recently failed servers (falling back to all servers if every
    /// candidate failed recently) and orders them by subnet affinity to
    /// `last_connected_ip`: same `/24`, then same `/16`, then others.
    /// Within each tier, candidates are shuffled randomly.
    pub fn prioritize(&mut self, servers: Vec<VpnServer>, now: Instant) -> Vec<VpnServer> {
        self.prioritize_excluding(servers, now, None)
    }

    /// Same as [`prioritize`](Self::prioritize), additionally excluding `exclude_ip`
    /// unless it is the only available candidate.
    pub fn prioritize_excluding(
        &mut self,
        servers: Vec<VpnServer>,
        now: Instant,
        exclude_ip: Option<&str>,
    ) -> Vec<VpnServer> {
        self.prune_expired(now);

        let mut available: Vec<VpnServer> = servers
            .iter()
            .filter(|s| !self.failed.contains_key(&s.ip) && exclude_ip != Some(s.ip.as_str()))
            .cloned()
            .collect();

        if available.is_empty() && !servers.is_empty() {
            if let Some(excluded) = exclude_ip {
                let others: Vec<VpnServer> = servers
                    .iter()
                    .filter(|s| s.ip != excluded)
                    .cloned()
                    .collect();
                if !others.is_empty() {
                    eprintln!(
                        "All other candidate servers recently failed; clearing failure history to retry"
                    );
                    self.failed.clear();
                    available = others;
                } else {
                    self.failed.clear();
                    available = servers;
                }
            } else {
                eprintln!(
                    "All {} candidate servers recently failed; clearing failure history to retry",
                    servers.len()
                );
                self.failed.clear();
                available = servers;
            }
        }

        let Some(anchor) = self.last_connected_ip else {
            available.shuffle(&mut rand::rng());
            return available;
        };

        let anchor_octets = anchor.octets();
        let mut same_24 = Vec::new();
        let mut same_16 = Vec::new();
        let mut others = Vec::new();

        for server in available {
            match server.ip.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    let octets = ip.octets();
                    if octets[0] == anchor_octets[0]
                        && octets[1] == anchor_octets[1]
                        && octets[2] == anchor_octets[2]
                    {
                        same_24.push(server);
                    } else if octets[0] == anchor_octets[0] && octets[1] == anchor_octets[1] {
                        same_16.push(server);
                    } else {
                        others.push(server);
                    }
                }
                Err(_) => others.push(server),
            }
        }

        let mut rng = rand::rng();
        same_24.shuffle(&mut rng);
        same_16.shuffle(&mut rng);
        others.shuffle(&mut rng);

        same_24.extend(same_16);
        same_24.extend(others);
        same_24
    }
}

pub fn build_http_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into()
}

pub fn fetch_global_ip(timeout: Duration, url: &str) -> Result<String, String> {
    // Use a fresh agent and Connection: close so every IP check opens a new
    // TCP socket and follows the current routing table (eth0 vs tun0).
    let agent = build_http_agent(timeout);
    let mut resp = agent
        .get(url)
        .header("User-Agent", "curl/8.0")
        .header("Connection", "close")
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;

    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response from {url} failed: {e}"))?;

    parse_ip_response(&body, url)
}

pub fn parse_ip_response(body: &str, url: &str) -> Result<String, String> {
    let ip = body.trim();
    if ip.is_empty() {
        return Err(format!("empty IP response from {url}"));
    }
    ip.parse::<IpAddr>()
        .map_err(|_| format!("invalid IP response from {url}: {ip:?}"))?;
    Ok(ip.to_string())
}

pub fn fetch_servers(
    agent: &ureq::Agent,
    url: &str,
    country_upper: &str,
) -> Result<Vec<VpnServer>, String> {
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;

    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading VPNGate CSV failed: {e}"))?;

    let servers = parse_vpngate_csv(&body, country_upper);
    Ok(servers)
}

pub fn parse_vpngate_csv(csv: &str, country_upper: &str) -> Vec<VpnServer> {
    let mut servers = Vec::new();

    for raw_line in csv.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        if line.contains("public-vpn-") {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 15 {
            continue;
        }

        let country = fields[6].trim();
        if !country.eq_ignore_ascii_case(country_upper) {
            continue;
        }

        let b64 = fields[14].trim();
        if b64.is_empty() {
            continue;
        }

        let Ok(ovpn_config) = STANDARD.decode(b64) else {
            continue;
        };

        servers.push(VpnServer {
            host_name: fields[0].trim().to_string(),
            ip: fields[1].trim().to_string(),
            country_short: country.to_ascii_uppercase(),
            ovpn_config,
        });
    }

    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vpngate_csv_filters_and_decodes() {
        let ovpn_b64 = STANDARD.encode("client\ndev tun\n");
        let csv = format!(
            "*vpn_servers\r\n\
             #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\r\n\
             vpn1,1.1.1.1,100,10,1000,Japan,JP,5,100,10,100,2wk,op,,{ovpn_b64}\r\n\
             public-vpn-123,2.2.2.2,100,10,1000,Japan,JP,5,100,10,100,2wk,op,,{ovpn_b64}\r\n\
             vpn2,3.3.3.3,100,10,1000,United States,US,5,100,10,100,2wk,op,,{ovpn_b64}\r\n\
             vpn3,4.4.4.4,100,10,1000,Japan,jp,5,100,10,100,2wk,op,,not_valid_base64!!!\r\n\
             short,line\r\n\
             *end\r\n"
        );

        let servers = parse_vpngate_csv(&csv, "JP");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].host_name, "vpn1");
        assert_eq!(servers[0].ip, "1.1.1.1");
        assert_eq!(servers[0].country_short, "JP");
        assert_eq!(servers[0].ovpn_config, b"client\ndev tun\n");
    }

    fn make_server(ip: &str) -> VpnServer {
        VpnServer {
            host_name: format!("vpn-{ip}"),
            ip: ip.to_string(),
            country_short: "JP".to_string(),
            ovpn_config: Vec::new(),
        }
    }

    #[test]
    fn test_selector_excludes_failed_and_expires() {
        let ttl = Duration::from_secs(60);
        let mut selector = ServerSelector::new(ttl);
        let t0 = Instant::now();

        selector.record_failure("1.1.1.1", t0);
        let servers = vec![make_server("1.1.1.1"), make_server("2.2.2.2")];

        let picked = selector.prioritize(servers.clone(), t0 + Duration::from_secs(10));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].ip, "2.2.2.2");

        // After TTL expires, 1.1.1.1 is eligible again.
        let picked_after = selector.prioritize(servers, t0 + Duration::from_secs(61));
        assert_eq!(picked_after.len(), 2);
    }

    #[test]
    fn test_selector_falls_back_when_all_failed() {
        let mut selector = ServerSelector::new(Duration::from_secs(60));
        let t0 = Instant::now();
        selector.record_failure("1.1.1.1", t0);
        selector.record_failure("2.2.2.2", t0);

        let servers = vec![make_server("1.1.1.1"), make_server("2.2.2.2")];
        let picked = selector.prioritize(servers, t0 + Duration::from_secs(5));
        assert_eq!(picked.len(), 2);
        assert_eq!(selector.failed_count(), 0);
    }

    #[test]
    fn test_selector_prioritizes_same_subnet() {
        let mut selector = ServerSelector::new(Duration::from_secs(60));
        let t0 = Instant::now();

        selector.record_success("10.20.30.1");
        // Simulate 10.20.30.1 later disconnecting so it is excluded on switch.
        selector.record_failure("10.20.30.1", t0);

        let servers = vec![
            make_server("192.168.1.1"), // other
            make_server("10.20.99.5"),  // same /16
            make_server("10.20.30.1"),  // recently failed
            make_server("10.20.30.42"), // same /24
        ];

        let picked = selector.prioritize(servers, t0 + Duration::from_secs(1));
        let ips: Vec<&str> = picked.iter().map(|s| s.ip.as_str()).collect();
        assert_eq!(ips, vec!["10.20.30.42", "10.20.99.5", "192.168.1.1"]);
    }

    #[test]
    fn test_selector_clear_affinity_and_exclude_current() {
        let mut selector = ServerSelector::new(Duration::from_secs(60));
        let t0 = Instant::now();

        selector.record_success("10.20.30.1");
        selector.clear_affinity();

        let servers = vec![
            make_server("10.20.30.1"),
            make_server("10.20.30.42"),
            make_server("192.168.1.1"),
        ];

        let picked = selector.prioritize_excluding(
            servers.clone(),
            t0 + Duration::from_secs(1),
            Some("10.20.30.1"),
        );
        assert_eq!(picked.len(), 2);
        assert!(picked.iter().all(|s| s.ip != "10.20.30.1"));

        // Even if all other servers recently failed, excluding current clears failures and avoids current.
        selector.record_failure("10.20.30.42", t0);
        selector.record_failure("192.168.1.1", t0);
        let picked_retry = selector.prioritize_excluding(
            servers,
            t0 + Duration::from_secs(2),
            Some("10.20.30.1"),
        );
        assert_eq!(picked_retry.len(), 2);
        assert!(picked_retry.iter().all(|s| s.ip != "10.20.30.1"));
        assert_eq!(selector.failed_count(), 0);
    }

    #[test]
    fn test_selector_exclude_only_server_falls_back() {
        let mut selector = ServerSelector::new(Duration::from_secs(60));
        let t0 = Instant::now();

        let servers = vec![make_server("10.20.30.1")];
        let picked = selector.prioritize_excluding(servers, t0, Some("10.20.30.1"));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].ip, "10.20.30.1");
    }

    #[test]
    fn test_parse_ip_response() {
        assert_eq!(
            parse_ip_response("203.0.113.5\n", "http://inet-ip.info").unwrap(),
            "203.0.113.5"
        );
        assert!(parse_ip_response("<!doctype html><html></html>", "http://inet-ip.info").is_err());
        assert!(parse_ip_response("   ", "http://inet-ip.info").is_err());
    }
}
