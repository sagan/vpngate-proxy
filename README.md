# vpngate-proxy

[VPNGate](http://www.vpngate.net/api/iphone/)から指定した国（デフォルト: `jp`）のVPNサーバを抽出してランダムに接続します  
`vproxy` により単一ポート (`8118`) で **HTTP / HTTPS / SOCKS5 / MASQUE (QUIC)** プロキシを提供します

> また、public-vpn-から始まるVPN(219.100.37.0/24等)は同じ場所からのアクセスになってしまうため除外しました

# 環境変数

| 変数名 | 説明 | デフォルト |
| --- | --- | --- |
| `VPNGATE_PROXY_COUNTRY` | 接続するVPNGateサーバの国コード（2文字のISO国コード、例: `jp`, `us`, `kr`） | `jp` |

# 起動

```bash
docker run --rm -it \
--cap-add=NET_ADMIN --device=/dev/net/tun \
--dns=1.1.1.1 --dns=8.8.8.8 --dns=9.9.9.9 \
-e VPNGATE_PROXY_COUNTRY=jp \
-p 8118:8118/tcp -p 8118:8118/udp \
vpngate-proxy
```

# 起動確認

proxy指定有り無しでcurlしてグローバルIPが異なっていれば成功です

```bash
$ curl inet-ip.info
$ curl inet-ip.info -x http://localhost:8118
$ curl inet-ip.info -x socks5://localhost:8118
```

# VPNサーバの切り替え

コンテナに `SIGUSR1` シグナルを送ると、現在のOpenVPN接続を切断して新しいランダムなVPNサーバへ切り替えます。

```bash
docker kill -s SIGUSR1 <container_name_or_id>
```
