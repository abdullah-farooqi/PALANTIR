#
# PALANTIR — Netdata Agent, built from source.
#
# No `# syntax=` directive on purpose: nothing here uses a BuildKit-only feature
# (no RUN --mount, no heredocs, no COPY --link), and the directive forces a pull
# of docker.io/docker/dockerfile from Docker Hub before the build can start. That
# pull fails on networks without Docker Hub access, for no benefit.
#
# The Netdata source tree is fetched at image-build time and never enters the
# PALANTIR repository.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY THE PIN IS A RELEASE TAG AND NOT A COMMIT SHA
# ─────────────────────────────────────────────────────────────────────────────
# GitHub will not serve an arbitrary commit over the git protocol:
#
#     $ git fetch --depth=1 origin f5bc7f2350
#     fatal: couldn't find remote ref f5bc7f2350
#
# Release tags are therefore the only immutable refs that clone reliably.
# "v2.11.0-466-nightly" is a *version string* produced by the nightly changelog
# job, NOT a git ref — `--branch v2.11.0-466-nightly` fails with
# "Remote branch not found".
#
# Every API contract PALANTIR depends on (the v3 data and weights endpoints,
# context names, weights methods, ML defaults) was diffed across v2.11.0,
# v2.11.1 and the nightly checkout and is identical, so v2.11.1 is safe to pin.
# To move the pin: pick the newest tag, then re-run the verification checklist
# in README.md against the running container.

FROM ubuntu:24.04 AS builder

ARG NETDATA_REPO=https://github.com/netdata/netdata.git
ARG NETDATA_REF=v2.11.1

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies only. Judy and libbpf are vendored inside the Netdata tree,
# so libjudy-dev and libbpf-dev are NOT required.

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential cmake pkg-config \
        libuv1-dev libssl-dev zlib1g-dev liblz4-dev liblzma-dev libzstd-dev \
        libcurl4-openssl-dev uuid-dev libsystemd-dev libyaml-dev \
        libgcrypt20-dev libelf-dev libcap-dev libbrotli-dev \
        libprotobuf-dev protobuf-compiler flex bison \
   && rm -rf /var/lib/apt/lists/*


WORKDIR /src
RUN git clone --depth=1 --branch "${NETDATA_REF}" "${NETDATA_REPO}" netdata \
 && cd netdata \
 && git submodule update --init src/aclk/aclk-schemas

# ACLK is compiled in unconditionally (CMakeLists.txt: ACLK_ALWAYS_BUILD) and
# there is no flag to remove it. It stays dormant because the node is never
# claimed, so it makes no outbound connection.
#
# Every -D below is a real CMake option. Unknown -D variables are SILENTLY
# IGNORED by CMake, so a typo disables nothing while appearing to work.
# Deliberately absent — these are not CMake options, do not re-add them:
#   ENABLE_CLOUD, ENABLE_ACLK, ENABLE_GO, ENABLE_PLUGIN_PROC,
#   ENABLE_PLUGIN_CGROUPS, ENABLE_PLUGIN_APPS, ENABLE_OPENTELEMETRY,
#   ENABLE_PLUGIN_LOGS_MANAGEMENT
#
# ENABLE_PLUGIN_NETWORK_VIEWER is OFF: the plugin builds fine, but its only
# useful output, the network-connections Function, is Cloud-SSO gated
# (SIGNED_ID|SAME_SPACE|SENSITIVE_DATA in network-viewer.c) and answers HTTP 412
# to every local caller. Building it produces nothing PALANTIR can use and costs
# compile time. Per-process socket attribution belongs to PALANTIR's PCAP
# pipeline.
  RUN cmake -B /build -S /src/netdata \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_DASHBOARD=OFF \
        -DENABLE_PLUGIN_GO=OFF \
        -DENABLE_PLUGIN_OTEL=OFF \
        -DENABLE_PLUGIN_PYTHON=OFF \
        -DENABLE_PLUGIN_CHARTS=OFF \
        -DENABLE_PLUGIN_SCRIPTS=OFF \
        -DENABLE_PLUGIN_NFACCT=OFF \
        -DENABLE_PLUGIN_FREEIPMI=OFF \
        -DENABLE_PLUGIN_CUPS=OFF \
        -DENABLE_PLUGIN_XENSTAT=OFF \
        -DENABLE_PLUGIN_SLABINFO=OFF \
        -DENABLE_PLUGIN_DEBUGFS=OFF \
        -DENABLE_PLUGIN_PERF=OFF \
        -DENABLE_PLUGIN_NETFLOW=OFF \
        -DENABLE_PLUGIN_SYSTEMD_JOURNAL=OFF \
        -DENABLE_PLUGIN_SYSTEMD_UNITS=OFF \
        -DENABLE_EXPORTER_MONGODB=OFF \
        -DENABLE_EXPORTER_PROMETHEUS_REMOTE_WRITE=OFF \
        -DENABLE_WEBRTC=OFF \
        -DENABLE_SENTRY=OFF \
        -DENABLE_PLUGIN_NETWORK_VIEWER=OFF \
        -DENABLE_PLUGIN_EBPF=ON \
        -DENABLE_ML=ON \
   && cmake --build /build --parallel "$(nproc)" \
   && cmake --install /build
# Derive the runtime package list from what the binaries actually link against.
#
# Do not hand-write this list. Ubuntu 24.04 renamed most of these in the 64-bit
# time_t transition (libuv1 -> libuv1t64, libssl3 -> libssl3t64, libpcap0.8 ->
# libpcap0.8t64, libcurl4 -> libcurl4t64, libelf1 -> libelf1t64,
# libgnutls30 -> libgnutls30t64), and libjudy0 does not exist at all because
# Judy is statically linked. A hand-written list fails to install and the image
# never builds.
 RUN set -eux; \
      ldd /usr/local/usr/sbin/netdata \
          /usr/local/usr/libexec/netdata/plugins.d/*.plugin* 2>/dev/null \
        | grep -oE '/[^[:space:]]+\.so[^[:space:]]*' \
        | sort -u \
        | xargs -r dpkg -S 2>/dev/null \
        | grep -v "diversion" \
        | cut -d: -f1 | sort -u > /tmp/runtime-pkgs.txt; \
      cat /tmp/runtime-pkgs.txt


# ── Runtime stage ───────────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=builder /tmp/runtime-pkgs.txt /tmp/runtime-pkgs.txt
# The ldd/dpkg -S derivation above silently drops libraries dpkg cannot
# attribute to a package (it failed for brotli, curl, elf, uv in practice,
# producing a runtime image whose binary cannot even start: exit 127).
# The runtime packages the binary needs are therefore also pinned
# explicitly; duplicate names from the derived list are harmless to apt.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      $(cat /tmp/runtime-pkgs.txt) wget tini curl \
      libyaml-0-2 libbrotli1 libcurl4t64 libelf1t64 libuv1t64 liblz4-1 \
 && rm -rf /var/lib/apt/lists/* /tmp/runtime-pkgs.txt

# Trailing slash = copy the CONTENTS of /usr/local, not the directory itself.
COPY --from=builder /usr/local/ /usr/local/

# Build-time guard: fail the build here if any linked library is still
# unresolved, instead of shipping an image whose binary dies at start with
# exit 127 ("error while loading shared libraries").
RUN set -eux; \
    ldd /usr/local/usr/sbin/netdata /usr/local/usr/libexec/netdata/plugins.d/*.plugin \
      | tee /tmp/ldd-check.txt; \
    if grep -q "not found" /tmp/ldd-check.txt; then \
      echo "FATAL: unresolved shared libraries:"; \
      grep "not found" /tmp/ldd-check.txt; \
      exit 1; \
    fi

RUN useradd --system --no-create-home --shell /usr/sbin/nologin netdata

COPY netdata.conf              /usr/local/etc/netdata/netdata.conf
COPY apps_groups.conf          /usr/local/etc/netdata/apps_groups.conf
COPY health_alarm_notify.conf  /usr/local/etc/netdata/health_alarm_notify.conf
COPY health.d/                 /usr/local/etc/netdata/health.d/

EXPOSE 19999

# wget, not curl: curl is not installed in this image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:19999/api/v1/info || exit 1

# The binary is at usr/sbin, NOT bin. Netdata's install layout is
# ${CMAKE_INSTALL_PREFIX}/usr/sbin/netdata (BINDIR is set to "usr/sbin" in
# CMakeLists.txt). The plugins live in ${prefix}/usr/libexec/netdata/plugins.d.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/usr/sbin/netdata", "-D"]
