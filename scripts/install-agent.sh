#!/usr/bin/env bash
# Compatibility entry point for the secure remote agent setup flow.
# Secret values are never accepted as arguments; use a private secrets file or
# enter them at the hidden prompts in setup-agent.sh.
set -Eeuo pipefail
set +x

INSTALL_DIR="${PALANTIR_AGENT_DIR:-/opt/palantir-agent}"
RAW_BASE="${PALANTIR_AGENT_RAW_BASE:-https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetry_pipeline}"
FORWARD_ARGS=()

usage() {
  cat <<'USAGE'
Usage: sudo ./scripts/install-agent.sh [options]

This compatibility installer downloads the current secure setup-agent flow.
It preserves common nonsecret options:
  --server URL             Central PALANTIR HTTPS origin
  --hostname NAME          Node hostname
  --ip IPv4                Address reachable from the central server
  --port PORT              Published Netdata port (legacy alias)
  --collector-port PORT    Published collector port
  --secrets-file PATH      Private .env.agent-secrets file from setup-central.sh
  --ca-cert PATH           Central Caddy root certificate
  --image IMAGE            Netdata image override
  --collector-image IMAGE  Collector image override
  --install-dir PATH       Agent config directory (default: /opt/palantir-agent)

Do not pass secret values as command-line arguments. Use --secrets-file or
omit it to enter the credentials at hidden prompts. For a local checkout,
prefer ./scripts/setup-agent.sh directly.
USAGE
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need_value() { (($# >= 2)) || die "$1 requires a value"; }

while (($#)); do
  case "$1" in
    --secret|--token|--enrollment-token)
      die "$1 is disabled because command-line secrets leak through shell history and process listings. Use --secrets-file or hidden prompts."
      ;;
    --server|--hostname|--ip|--collector-port|--secrets-file|--ca-cert|--image|--collector-image)
      need_value "$1" "$@"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --port)
      need_value "$1" "$@"
      FORWARD_ARGS+=(--netdata-port "$2")
      shift 2
      ;;
    --netdata-port)
      need_value "$1" "$@"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    --install-dir)
      need_value "$1" "$@"
      INSTALL_DIR="$2"
      FORWARD_ARGS+=("$1" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    http://*|https://*)
      [[ ! "${FORWARD_ARGS[*]}" =~ --server ]] || die "Central URL was supplied more than once."
      FORWARD_ARGS+=(--server "$1")
      shift
      ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "Run this installer as root, for example: sudo ./scripts/install-agent.sh --help"
command -v curl >/dev/null 2>&1 || die "curl is required to download the secure setup files."
command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Engine and the Compose plugin first."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
install -d -m 0700 "${TMP_DIR}/scripts"
curl -fsSL "${RAW_BASE}/scripts/setup-agent.sh" -o "${TMP_DIR}/scripts/setup-agent.sh" || die "Could not download setup-agent.sh from ${RAW_BASE}."
curl -fsSL "${RAW_BASE}/docker-compose.agent.yml" -o "${TMP_DIR}/docker-compose.agent.yml" || die "Could not download docker-compose.agent.yml from ${RAW_BASE}."
chmod 0700 "${TMP_DIR}/scripts/setup-agent.sh"

bash "${TMP_DIR}/scripts/setup-agent.sh" --install-dir "$INSTALL_DIR" "${FORWARD_ARGS[@]}"
