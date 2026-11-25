FROM alpine:3.24

RUN apk add --no-cache \
    bash \
    openvpn \
    curl \
    coreutils \
    iproute2 \
    procps \
    util-linux

COPY --from=ghcr.io/0x676e67/vproxy:latest /bin/vproxy /bin/vproxy
COPY start.sh /bin/

ENV VPNGATE_PROXY_COUNTRY=jp

EXPOSE 8118/tcp 8118/udp

CMD [ "start.sh" ]
