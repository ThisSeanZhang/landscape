FROM debian:trixie-slim AS runtime

RUN --mount=type=secret,id=resolver,target=/etc/resolv.conf,mode=0444 \
    apt-get update -o APT::Update::Error-Mode=any \
    && apt-get install -y --no-install-recommends curl iproute2 libelf1t64 openssl python3 udhcpc \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

FROM runtime AS acme-tools
RUN --mount=type=secret,id=resolver,target=/etc/resolv.conf,mode=0444 \
    apt-get update -o APT::Update::Error-Mode=any \
    && apt-get install -y --no-install-recommends pebble python3-dnslib \
    && rm -rf /var/lib/apt/lists/*

FROM acme-tools AS acme
COPY landscape-webserver /usr/local/bin/

FROM runtime AS lab
COPY landscape-webserver /usr/local/bin/
