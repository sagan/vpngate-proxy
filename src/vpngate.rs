use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::seq::SliceRandom;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnServer {
    pub host_name: String,
    pub ip: String,
    pub country_short: String,
    pub ovpn_config: Vec<u8>,
}

pub fn build_http_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into()
}

pub fn fetch_global_ip(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;

    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response from {url} failed: {e}"))?;

    let ip = body.trim();
    if ip.is_empty() {
        return Err(format!("empty IP response from {url}"));
    }
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

    let mut servers = parse_vpngate_csv(&body, country_upper);
    servers.shuffle(&mut rand::rng());
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
}
