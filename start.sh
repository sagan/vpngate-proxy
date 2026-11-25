#!/usr/bin/env bash

VPNGATE_URL=http://www.vpngate.net/api/iphone/
COUNTRY="${VPNGATE_PROXY_COUNTRY:-jp}"
COUNTRY="${COUNTRY^^}"

echo "VPNGATE_PROXY_COUNTRY=$COUNTRY"

function global_ip {
  curl -s inet-ip.info
}

# vpn connect func
function connect {
  while :; do 
    echo start
    while read line; do 
      line=$(echo $line | cut -d ',' -f 15)
      line=$(echo $line | tr -d '\r')
      openvpn <(echo "$line" | base64 -d) ;
    done < <(curl -s $VPNGATE_URL | awk -F',' -v cc="$COUNTRY" 'toupper($7) == cc' | grep -v public-vpn- | sort -R )
    echo end
  done
}

function setup_policy_routing {
  local eth_if eth_gw eth_ip eth_net
  eth_if=$(ip route show default | awk '{print $5; exit}')
  eth_gw=$(ip route show default | awk '{print $3; exit}')
  if [ -z "$eth_if" ] || [ -z "$eth_gw" ]; then
    echo "Warning: could not detect default interface/gateway, skipping policy routing setup"
    return
  fi

  eth_ip=$(ip -4 addr show dev "$eth_if" | awk '/inet /{print $2; exit}' | cut -d/ -f1)
  eth_net=$(ip route show dev "$eth_if" proto kernel scope link | awk '{print $1; exit}')
  if [ -z "$eth_ip" ]; then
    echo "Warning: could not detect IP for $eth_if, skipping policy routing setup"
    return
  fi

  if [ -n "$eth_net" ]; then
    ip route replace "$eth_net" dev "$eth_if" src "$eth_ip" table 100
  fi
  ip route replace default via "$eth_gw" dev "$eth_if" table 100
  ip rule del from "$eth_ip" table 100 2>/dev/null || true
  ip rule add from "$eth_ip" table 100 priority 100
  echo "Policy routing configured: from $eth_ip -> table 100 (via $eth_gw dev $eth_if)"
}

setup_policy_routing

BEFORE_IP="$(global_ip)"

# start proxy (HTTP/HTTPS/SOCKS5 on TCP 8118, MASQUE on UDP 8118)
vproxy run --bind 0.0.0.0:8118 auto &
if [ "$VPNGATE_PROXY_UDP" = "1" ]
then
  sleep 1
  vproxy run --bind 0.0.0.0:8118 quic &
fi

# connect vpn
connect &

# vpn check
while :; do
  sleep 5
  AFTER_IP=$(global_ip)
  result=$?
  echo "before=$BEFORE_IP after=$AFTER_IP"
  if [ $result -ne 0 ]; then
    pkill openvpn
  elif [ "$BEFORE_IP" = "$AFTER_IP" ]; then
    pkill openvpn
  else 
    sleep 55
  fi
done
