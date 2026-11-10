# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio del libro: tor compilato dai sorgenti + Chutney, versioni fissate.
# Build:  make -C labs/it immagine      Uso: vedi labs/it/laboratorio/README.md e capitolo 19.
#
# Dietro un proxy HTTPS che re-termina TLS (per esempio un ambiente cloud):
#   make -C labs/it immagine PROXY_CA=/percorso/della/ca-del-proxy.crt
# La CA arriva come segreto BuildKit: serve solo durante i RUN che scaricano e non resta
# nell'immagine (mode=0444: apt scarica come utente _apt; è un certificato pubblico, non
# una chiave); con il segreto, apt usa HTTPS. Senza segreto la build resta quella di sempre.
FROM debian:trixie-slim AS build
ARG TOR_VERSION=0.4.9.13
# Commit del tag tor-0.4.9.13 (tag firmato da David Goulet, B744 17ED DF22 AC9F 9E90 F491 42E8 6A2A 11F4 8D36)
ARG TOR_COMMIT=3c575400909efe6599d88e61e7daf0012655ca44
RUN --mount=type=secret,id=proxy_ca,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|' /etc/apt/sources.list.d/debian.sources \
      && echo 'Acquire::https::CAInfo "/run/secrets/proxy_ca";' > /etc/apt/apt.conf.d/99ca-proxy; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends \
      build-essential automake autoconf libtool pkg-config git ca-certificates \
      libevent-dev libssl-dev zlib1g-dev liblzma-dev libzstd-dev \
    && rm -f /etc/apt/apt.conf.d/99ca-proxy && rm -rf /var/lib/apt/lists/*
RUN --mount=type=secret,id=proxy_ca,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then export GIT_SSL_CAINFO=/run/secrets/proxy_ca; fi \
    && git clone --depth 1 --branch tor-${TOR_VERSION} \
      https://gitlab.torproject.org/tpo/core/tor.git /src/tor \
    && test "$(git -C /src/tor rev-parse HEAD)" = "${TOR_COMMIT}"
WORKDIR /src/tor
# --enable-gpl: necessario per il modulo di prova di lavoro (PoW) degli onion service (cap. 15).
RUN ./autogen.sh && ./configure --enable-gpl --disable-asciidoc --disable-unittests --prefix=/opt/tor \
    && make -j"$(nproc)" && make install

FROM debian:trixie-slim
ARG CHUTNEY_COMMIT=6cc158868d722e652975cb4efd5b278d95ff2fbb
RUN --mount=type=secret,id=proxy_ca,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|' /etc/apt/sources.list.d/debian.sources \
      && echo 'Acquire::https::CAInfo "/run/secrets/proxy_ca";' > /etc/apt/apt.conf.d/99ca-proxy; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends \
      libevent-2.1-7t64 libssl3t64 zlib1g liblzma5 libzstd1 \
      python3 python3-venv git ca-certificates procps iproute2 tcpdump tshark \
      obfs4proxy snowflake-client curl \
    && rm -f /etc/apt/apt.conf.d/99ca-proxy && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/tor /opt/tor
ENV PATH=/opt/tor/bin:$PATH
# DirPort su 127.0.0.1 come l'OrPort (motivazione nel file della patch).
COPY chutney-dirport-loopback.patch /tmp/
RUN --mount=type=secret,id=proxy_ca,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
      export GIT_SSL_CAINFO=/run/secrets/proxy_ca PIP_CERT=/run/secrets/proxy_ca; fi \
    && git clone https://gitlab.torproject.org/tpo/core/chutney.git /opt/chutney \
    && git -C /opt/chutney checkout ${CHUTNEY_COMMIT} \
    && test "$(git -C /opt/chutney rev-parse HEAD)" = "${CHUTNEY_COMMIT}" \
    && git -C /opt/chutney apply --verbose /tmp/chutney-dirport-loopback.patch \
    && grep -q 'DirPort {addr_and_port_str(ip, n.dirport.unwrap())' /opt/chutney/lib/chutney/tor/torrc.py \
    && rm /tmp/chutney-dirport-loopback.patch \
    && python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir /opt/chutney stem pytest
ENV PATH=/opt/venv/bin:$PATH \
    CHUTNEY_PATH=/opt/chutney \
    CHUTNEY_DATA_DIR=/lab/net
WORKDIR /lab
CMD ["bash"]
