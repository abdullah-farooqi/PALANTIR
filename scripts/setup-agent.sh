#!/usr/bin/env bash
# Configure and start the Netdata + PALANTIR host collector on a remote Linux host.
set -Eeuo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="${PALANTIR_AGENT_DIR:-/opt/palantir-agent}"
SECRETS_FILE=""
CA_CERT=""
NODE_IP=""
NODE_NAME=""
NETDATA_PORT="19999"
COLLECTOR_PORT="20000"
SERVER_URL=""
WEBHOOK_SECRET=""
ENROLL_TOKEN=""
AGENT_TOKEN=""
NETDATA_IMAGE="abdullahahmadfarooqi/palantir-netdata:latest"
COLLECTOR_IMAGE="abdullahahmadfarooqi/palantir-host-collector:latest"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/setup-agent.sh [options]

Options:
  --secrets-file PATH  Private .env.agent-secrets file made by setup-central.sh
  --ca-cert PATH       Caddy root certificate copied from the central server
  --ip IPv4            Address the central server can reach on this host
  --hostname NAME      Node name (default: this machine's hostname)
  --netdata-port PORT  Published Netdata port (default: 19999)
  --collector-port PORT Published collector port (default: 20000)
  --install-dir PATH   Install directory (default: /opt/palantir-agent)
  -h, --help           Show this help

Secrets can also be entered at hidden prompts. They are never accepted as
command-line arguments or printed by this script.
EOF
}

while (($#)); do
  case "$1" in
    --secrets-file) (($# >= 2)) || die "--secrets-file requires a path"; SECRETS_FILE="$2"; shift 2 ;;
    --ca-cert) (($# >= 2)) || die "--ca-cert requires a path"; CA_CERT="$2"; shift 2 ;;
    --ip) (($# >= 2)) || die "--ip requires an IPv4 address"; NODE_IP="$2"; shift 2 ;;
    --hostname) (($# >= 2)) || die "--hostname requires a name"; NODE_NAME="$2"; shift 2 ;;
    --netdata-port) (($# >= 2)) || die "--netdata-port requires a port"; NETDATA_PORT="$2"; shift 2 ;;
    --collector-port) (($# >= 2)) || die "--collector-port requires a port"; COLLECTOR_PORT="$2"; shift 2 ;;
    --install-dir) (($# >= 2)) || die "--install-dir requires a path"; INSTALL_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "Run with sudo so the agent can read host telemetry and install its protected config."
[[ -f "${REPO_ROOT}/docker-compose.agent.yml" ]] || die "Run this script from a PALANTIR repository checkout."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required."
docker info >/dev/null 2>&1 || die "Docker is unavailable; check that Docker Engine is running."
[[ -t 0 || -r /dev/tty ]] || die "Interactive input is required when values are not provided in --secrets-file."

if [[ -n "$SECRETS_FILE" ]]; then
  [[ -r "$SECRETS_FILE" ]] || die "Cannot read secrets file: ${SECRETS_FILE}"
  chmod 600 "$SECRETS_FILE" || die "Could not restrict permissions on the secrets file."
  SERVER_URL="$(awk -F= '$1 == "PALANTIR_SERVER_URL" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
  WEBHOOK_SECRET="$(awk -F= '$1 == "PALANTIR_WEBHOOK_SECRET" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
  ENROLL_TOKEN="$(awk -F= '$1 == "PALANTIR_API_ENROLL_TOKEN" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
  AGENT_TOKEN="$(awk -F= '$1 == "PALANTIR_AGENT_TOKEN" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
  NETDATA_IMAGE="$(awk -F= '$1 == "PALANTIR_NETDATA_IMAGE" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
  COLLECTOR_IMAGE="$(awk -F= '$1 == "PALANTIR_COLLECTOR_IMAGE" { sub(/^[^=]*=/, ""); print; exit }' "$SECRETS_FILE")"
fi

prompt_value() {
  local label="$1" default="$2" response
  if [[ -n "$default" ]]; then
    read -r -p "${label} [${default}]: " response </dev/tty || die "Could not read ${label}."
    printf '%s' "${response:-$default}"
  else
    read -r -p "${label}: " response </dev/tty || die "Could not read ${label}."
    printf '%s' "$response"
  fi
}

prompt_secret() {
  local label="$1" response
  read -r -s -p "${label}: " response </dev/tty || die "Could not read secret input."
  printf '\n' >/dev/tty
  printf '%s' "$response"
}

valid_secret() {
  local value="$1"
  [[ ${#value} -ge 32 && "$value" =~ ^[A-Za-z0-9._-]+$ ]]
}

valid_ipv4() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  awk -F. '{ for (i = 1; i <= 4; i++) if ($i > 255) exit 1 }' <<<"$candidate" || return 1
  [[ "$candidate" != 0.0.0.0 && "$candidate" != 127.* ]]
}

valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 > 0 && 10#$1 <= 65535 ))
}

if [[ -z "$SERVER_URL" ]]; then
  SERVER_URL="$(prompt_value 'Central PALANTIR HTTPS URL' 'https://palantir.home.arpa')"
fi
[[ "$SERVER_URL" =~ ^https://[^/[:space:]]+/?$ ]] || die "Use the central HTTPS origin, for example https://palantir.home.arpa."
SERVER_URL="${SERVER_URL%/}"

if [[ -z "$NODE_NAME" ]]; then
  DEFAULT_NAME="$(hostname -s 2>/dev/null || printf 'remote-node')"
  NODE_NAME="$(prompt_value 'Unique node hostname' "$DEFAULT_NAME")"
fi
[[ "$NODE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]] || die "Hostname must be 1-63 letters, digits, dots, or hyphens and start with a letter or digit."

if [[ -z "$NODE_IP" ]]; then
  CENTRAL_HOST="${SERVER_URL#https://}"
  CENTRAL_HOST="${CENTRAL_HOST%%:*}"
  DETECTED_IP="$(ip -4 route get "$CENTRAL_HOST" 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)"
  NODE_IP="$(prompt_value 'IPv4 address reachable from the central server' "$DETECTED_IP")"
fi
valid_ipv4 "$NODE_IP" || die "Provide a valid IPv4 address reachable from the central PALANTIR server."

NETDATA_PORT="$(prompt_value 'Published Netdata port' "$NETDATA_PORT")"
COLLECTOR_PORT="$(prompt_value 'Published host collector port' "$COLLECTOR_PORT")"
valid_port "$NETDATA_PORT" || die "Netdata port must be between 1 and 65535."
valid_port "$COLLECTOR_PORT" || die "Collector port must be between 1 and 65535."

if [[ -z "$CA_CERT" ]]; then
  CA_CERT="$(prompt_value 'Path to the central Caddy root certificate' '')"
fi
[[ -r "$CA_CERT" && -f "$CA_CERT" ]] || die "Cannot read the central root certificate: ${CA_CERT}"

if [[ -z "$WEBHOOK_SECRET" ]]; then
  WEBHOOK_SECRET="$(prompt_secret 'Central PALANTIR_WEBHOOK_SECRET (hidden)')"
fi
if [[ -z "$ENROLL_TOKEN" ]]; then
  ENROLL_TOKEN="$(prompt_secret 'Central PALANTIR_API_ENROLL_TOKEN (hidden)')"
fi
if [[ -z "$AGENT_TOKEN" ]]; then
  AGENT_TOKEN="$(prompt_secret 'Central AGENT_AUTH_TOKEN (hidden)')"
fi
valid_secret "$WEBHOOK_SECRET" || die "Webhook secret must be at least 32 characters and use only letters, digits, dot, underscore, or hyphen."
valid_secret "$ENROLL_TOKEN" || die "Enrollment token must be at least 32 characters and use only letters, digits, dot, underscore, or hyphen."
valid_secret "$AGENT_TOKEN" || die "Collector token must be at least 32 characters and use only letters, digits, dot, underscore, or hyphen."

[[ "$NETDATA_IMAGE" =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$ ]] || die "Invalid Netdata image reference in secrets file."
[[ "$COLLECTOR_IMAGE" =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$ ]] || die "Invalid collector image reference in secrets file."
[[ ! -e "${INSTALL_DIR}/.env.agent" ]] || die "${INSTALL_DIR}/.env.agent already exists; preserving it. Back it up/remove it deliberately before reconfiguring."

install -d -m 0700 "$INSTALL_DIR"
install -m 0644 "${REPO_ROOT}/docker-compose.agent.yml" "${INSTALL_DIR}/docker-compose.agent.yml"
install -m 0644 "$CA_CERT" "${INSTALL_DIR}/central-ca.crt"
TEMP_ENV="$(mktemp "${INSTALL_DIR}/.env.agent.tmp.XXXXXX")"
trap 'rm -f "${TEMP_ENV:-}"' EXIT
{
  printf 'PALANTIR_SERVER_URL=%s\n' "$SERVER_URL"
  printf 'NODE_HOSTNAME=%s\n' "$NODE_NAME"
  printf 'NODE_ADVERTISED_URL=http://%s:%s\n' "$NODE_IP" "$NETDATA_PORT"
  printf 'COLLECTOR_ADVERTISED_URL=http://%s:%s\n' "$NODE_IP" "$COLLECTOR_PORT"
  printf 'NETDATA_PORT=%s\n' "$NETDATA_PORT"
  printf 'COLLECTOR_PORT=%s\n' "$COLLECTOR_PORT"
  printf 'PALANTIR_WEBHOOK_SECRET=%s\n' "$WEBHOOK_SECRET"
  printf 'PALANTIR_API_ENROLL_TOKEN=%s\n' "$ENROLL_TOKEN"
  printf 'PALANTIR_AGENT_TOKEN=%s\n' "$AGENT_TOKEN"
  printf 'PALANTIR_CA_CERT=/etc/ssl/certs/palantir-central-ca.crt\n'
  printf 'PALANTIR_NETDATA_IMAGE=%s\n' "$NETDATA_IMAGE"
  printf 'PALANTIR_COLLECTOR_IMAGE=%s\n' "$COLLECTOR_IMAGE"
} >"$TEMP_ENV"
chmod 600 "$TEMP_ENV"
mv "$TEMP_ENV" "${INSTALL_DIR}/.env.agent"
TEMP_ENV=""
trap - EXIT

COMPOSE=(docker compose --env-file "${INSTALL_DIR}/.env.agent" -f "${INSTALL_DIR}/docker-compose.agent.yml")
printf '\n==> Pulling sensor and collector images\n'
"${COMPOSE[@]}" pull sensor collector enroller
printf '\n==> Starting remote telemetry services\n'
"${COMPOSE[@]}" up -d

printf '\n==> Waiting for Netdata and collector health\n'
healthy=false
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${NETDATA_PORT}/api/v1/info" >/dev/null \
    && curl -fsS --max-time 2 "http://127.0.0.1:${COLLECTOR_PORT}/healthz" >/dev/null; then
    healthy=true
    break
  fi
  sleep 2
done
[[ "$healthy" == true ]] || die "Agent endpoints did not become healthy. Inspect: ${COMPOSE[*]} logs"

enrolled=false
for _ in $(seq 1 60); do
  state="$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' palantir-agent-enroller 2>/dev/null || true)"
  if [[ "$state" == exited:0 ]]; then
    enrolled=true
    break
  fi
  sleep 2
done

cat <<EOF

Remote telemetry services are healthy.
  Node:      ${NODE_NAME}
  Netdata:   http://${NODE_IP}:${NETDATA_PORT}
  Collector: http://${NODE_IP}:${COLLECTOR_PORT}
  Config:    ${INSTALL_DIR}/.env.agent (mode 600)
EOF
if [[ "$enrolled" == true ]]; then
  printf 'Central enrollment succeeded.\n'
else
  printf 'Enrollment has not completed; inspect with: docker logs palantir-agent-enroller\n'
fi
cat <<EOF

Allow inbound TCP ${NETDATA_PORT} and ${COLLECTOR_PORT} from the central server
only. The central server must be able to reach the advertised URLs above.
EOF
