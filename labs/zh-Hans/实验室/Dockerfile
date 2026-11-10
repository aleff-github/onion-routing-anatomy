# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 简体中文版私有 Tor 实验环境：从源码构建 Tor 并集成 Chutney。
# 构建：make image。使用说明参见 README.md 和第 19 章。
FROM debian:trixie-slim AS build
ARG TOR_VERSION=0.4.9.13
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential automake autoconf libtool pkg-config git ca-certificates \
      libevent-dev libssl-dev zlib1g-dev liblzma-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch tor-${TOR_VERSION} \
      https://gitlab.torproject.org/tpo/core/tor.git /src/tor
WORKDIR /src/tor
# --enable-gpl 用于启用洋葱服务工作量证明模块（第 15 章）。
RUN ./autogen.sh && ./configure --enable-gpl --disable-asciidoc --disable-unittests --prefix=/opt/tor \
    && make -j"$(nproc)" && make install

FROM debian:trixie-slim
ARG CHUTNEY_COMMIT=6cc1588
RUN apt-get update && apt-get install -y --no-install-recommends \
      libevent-2.1-7t64 libssl3t64 zlib1g liblzma5 libzstd1 \
      python3 python3-venv git ca-certificates procps iproute2 tcpdump tshark \
      obfs4proxy snowflake-client curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/tor /opt/tor
ENV PATH=/opt/tor/bin:$PATH
RUN git clone https://gitlab.torproject.org/tpo/core/chutney.git /opt/chutney \
    && git -C /opt/chutney checkout ${CHUTNEY_COMMIT} \
    && python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir /opt/chutney stem pytest
ENV PATH=/opt/venv/bin:$PATH \
    CHUTNEY_PATH=/opt/chutney \
    CHUTNEY_DATA_DIR=/lab/net
WORKDIR /lab
CMD ["bash"]
