use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub gateway: String,
    pub interface: String,
}

pub fn parse_default_route(output: &str) -> Option<DefaultRoute> {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut gateway = None;
        let mut interface = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "via" if i + 1 < tokens.len() => {
                    gateway = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "dev" if i + 1 < tokens.len() => {
                    interface = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if let (Some(gw), Some(iface)) = (gateway, interface) {
            return Some(DefaultRoute {
                gateway: gw,
                interface: iface,
            });
        }
    }
    None
}

pub fn parse_ipv4_addr(output: &str) -> Option<String> {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for window in tokens.windows(2) {
            if window[0] == "inet" {
                let ip = window[1].split('/').next().unwrap_or("");
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

pub fn parse_kernel_subnet(output: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .find(|tok| !tok.is_empty())
        .map(|s| s.to_string())
}

fn run_ip(args: &[&str]) -> Result<String, String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute `ip {}`: {e}", args.join(" ")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "`ip {}` exited with {}: {}",
            args.join(" "),
            out.status,
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn setup_policy_routing() {
    let default_out = match run_ip(&["route", "show", "default"]) {
        Ok(out) => out,
        Err(err) => {
            eprintln!("Warning: {err}, skipping policy routing setup");
            return;
        }
    };

    let Some(route) = parse_default_route(&default_out) else {
        eprintln!("Warning: could not detect default interface/gateway, skipping policy routing setup");
        return;
    };

    let addr_out = match run_ip(&["-4", "addr", "show", "dev", &route.interface]) {
        Ok(out) => out,
        Err(err) => {
            eprintln!("Warning: {err}, skipping policy routing setup");
            return;
        }
    };

    let Some(eth_ip) = parse_ipv4_addr(&addr_out) else {
        eprintln!(
            "Warning: could not detect IP for {}, skipping policy routing setup",
            route.interface
        );
        return;
    };

    let net_out = run_ip(&[
        "route",
        "show",
        "dev",
        &route.interface,
        "proto",
        "kernel",
        "scope",
        "link",
    ])
    .unwrap_or_default();

    if let Some(eth_net) = parse_kernel_subnet(&net_out)
        && let Err(err) = run_ip(&[
            "route",
            "replace",
            &eth_net,
            "dev",
            &route.interface,
            "src",
            &eth_ip,
            "table",
            "100",
        ])
    {
        eprintln!("Warning: {err}");
    }

    if let Err(err) = run_ip(&[
        "route",
        "replace",
        "default",
        "via",
        &route.gateway,
        "dev",
        &route.interface,
        "table",
        "100",
    ]) {
        eprintln!("Warning: {err}");
        return;
    }

    let _ = Command::new("ip")
        .args(["rule", "del", "from", &eth_ip, "table", "100"])
        .output();

    if let Err(err) = run_ip(&[
        "rule",
        "add",
        "from",
        &eth_ip,
        "table",
        "100",
        "priority",
        "100",
    ]) {
        eprintln!("Warning: {err}");
        return;
    }

    println!(
        "Policy routing configured: from {eth_ip} -> table 100 (via {} dev {})",
        route.gateway, route.interface
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_route() {
        let sample = "default via 172.17.0.1 dev eth0 \n";
        assert_eq!(
            parse_default_route(sample),
            Some(DefaultRoute {
                gateway: "172.17.0.1".to_string(),
                interface: "eth0".to_string(),
            })
        );
    }

    #[test]
    fn test_parse_default_route_missing() {
        assert_eq!(parse_default_route(""), None);
        assert_eq!(parse_default_route("default dev eth0\n"), None);
    }

    #[test]
    fn test_parse_ipv4_addr() {
        let sample = "2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\n";
        assert_eq!(parse_ipv4_addr(sample), Some("172.17.0.2".to_string()));
    }

    #[test]
    fn test_parse_kernel_subnet() {
        let sample = "172.17.0.0/16 proto kernel scope link src 172.17.0.2 \n";
        assert_eq!(
            parse_kernel_subnet(sample),
            Some("172.17.0.0/16".to_string())
        );
    }
}
