FROM debian:trixie-slim

RUN --mount=type=secret,id=resolver,target=/etc/resolv.conf,mode=0444 \
    apt-get update -o APT::Update::Error-Mode=any \
    && apt-get install -y --no-install-recommends curl iproute2 libelf1t64 openssl python3 udhcpc \
    && rm -rf /var/lib/apt/lists/*

COPY landscape-webserver /usr/local/bin/
CMD ["sleep", "infinity"]
