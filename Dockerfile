FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM alpine:3.24

RUN apk add --no-cache \
    openvpn \
    iproute2

COPY --from=ghcr.io/0x676e67/vproxy:latest /bin/vproxy /bin/vproxy
COPY --from=builder /src/target/release/vpngate-proxy /bin/vpngate-proxy

ENV VPNGATE_PROXY_COUNTRY=jp

EXPOSE 8118/tcp 8118/udp

CMD [ "vpngate-proxy" ]
