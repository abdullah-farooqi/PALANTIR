#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR — Zero-Touch Remote Agent Installer & Enroller
#
# Run this script on a remote Linux host to deploy the Compose-managed Netdata
# sensor and PALANTIR host collector bundle.
#
# Quickstart Usage:
#   curl -fsSL https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetry_pipeline/scripts/install-agent.sh | sudo bash -s -- --server https://<PALANTIR_PROXY_HOST> --secret '<CENTRAL_WEBHOOK_SECRET>' --enrollment-token '<RESTRICTED_ENROLLMENT_TOKEN>'
#
# Or run locally:
#   sudo ./scripts/install-agent.sh --server https://palantir.home.arpa --ca-cert ./caddy-root.crt --secret '<CENTRAL_WEBHOOK_SECRET>' --enrollment-token '<RESTRICTED_ENROLLMENT_TOKEN>'
#
# Flags:
#   --server <URL>     PALANTIR HTTPS proxy URL (required when passing an API token)
#   --hostname <NAME>  Custom hostname for this node (default: detected hostname)
#   --ip <IP>          Custom advertised IP (default: detected primary IP)
#   --port <PORT>      Sensor port (default: 19999)
#   --collector-port   Collector port (default: 20000)
#   --secret <SECRET>  Webhook secret configured on the central server
#   --enrollment-token <TOKEN> Optional restricted node-enrollment API token
#   --ca-cert <PATH>   Caddy/private root CA used to validate the central HTTPS certificate
#   --image <IMAGE>    Custom Netdata image
#   --collector-image <IMAGE> Custom PALANTIR host collector image
#   --install-dir <PATH> Compose deployment directory (default: /opt/palantir-agent)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Visual formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SERVER_URL=""
NODE_HOSTNAME=""
NODE_IP=""
PORT="19999"
COLLECTOR_PORT="20000"
SECRET="${PALANTIR_WEBHOOK_SECRET:-}"
DOCKER_IMAGE="abdullahahmadfarooqi/palantir-netdata:latest"
COLLECTOR_IMAGE="abdullahahmadfarooqi/palantir-host-collector:latest"
INSTALL_DIR="${PALANTIR_AGENT_DIR:-/opt/palantir-agent}"
AGENT_TOKEN=""
ENROLL_TOKEN="${PALANTIR_API_ENROLL_TOKEN:-}"
CENTRAL_CA_CERT="${PALANTIR_CA_CERT_FILE:-}"

# 1. Parse arguments (accepts positional server URL or flags)
while [[ $# -gt 0 ]]; do
  case $1 in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --hostname)
      NODE_HOSTNAME="$2"
      shift 2
      ;;
    --ip)
      NODE_IP="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --collector-port)
      COLLECTOR_PORT="$2"
      shift 2
      ;;
    --secret)
      SECRET="$2"
      shift 2
      ;;
    --image)
      DOCKER_IMAGE="$2"
      shift 2
      ;;
    --collector-image)
      COLLECTOR_IMAGE="$2"
      shift 2
      ;;
    --token)
      AGENT_TOKEN="$2"
      shift 2
      ;;
    --enrollment-token)
      ENROLL_TOKEN="$2"
      shift 2
      ;;
    --ca-cert)
      CENTRAL_CA_CERT="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 <PALANTIR_SERVER_URL> [options]"
      echo "Options:"
      echo "  --server <URL>     PALANTIR Central Server URL (e.g. http://192.168.1.50:8000)"
      echo "  --hostname <NAME>  Custom node hostname"
      echo "  --ip <IP>          Custom node advertised IP"
      echo "  --port <PORT>      Port for Netdata sensor (default: 19999)"
      echo "  --collector-port <PORT> Port for host collector (default: 20000)"
      echo "  --secret <SECRET>  Shared secret for webhooks"
      echo "  --image <IMAGE>    Netdata sensor image"
      echo "  --collector-image <IMAGE> Host collector image"
      echo "  --token <TOKEN>    Optional token required by the host collector"
      echo "  --enrollment-token <TOKEN> Restricted API token for automatic node registration"
      echo "  --ca-cert <PATH>   Root CA certificate for a private HTTPS server"
      echo "  --install-dir <PATH> Compose deployment directory (default: /opt/palantir-agent)"
      exit 0
      ;;
    http*|https*)
      SERVER_URL="$1"
      shift
      ;;
    *)
      echo -e "${RED}[ERROR] Unknown argument: $1${NC}"
      exit 1
      ;;
  esac
done

if [ -z "$SERVER_URL" ]; then
  echo -e "${RED}[ERROR] PALANTIR server URL is required.${NC}"
  echo "Usage: $0 http://<SYSADMIN_IP>:8000"
  exit 1
fi

if [ -z "$SECRET" ]; then
  echo -e "${RED}[ERROR] Set PALANTIR_WEBHOOK_SECRET or pass --secret with the value configured on the central server.${NC}"
  exit 1
fi

if [ -n "$ENROLL_TOKEN" ] && [[ "$SERVER_URL" != https://* ]]; then
  echo -e "${RED}[ERROR] Use an HTTPS central URL when sending the enrollment token.${NC}"
  exit 1
fi
if [ -n "$CENTRAL_CA_CERT" ] && [ ! -r "$CENTRAL_CA_CERT" ]; then
  echo -e "${RED}[ERROR] Cannot read central CA certificate: ${CENTRAL_CA_CERT}${NC}"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}[ERROR] Run this installer as root so it can install the Compose config and access Docker.${NC}"
  echo "Use: curl ... | sudo bash -s -- --server <URL> --secret '<CENTRAL_WEBHOOK_SECRET>'"
  exit 1
fi

SERVER_URL="${SERVER_URL%/}" # Strip trailing slash
CENTRAL_CURL_CA=()
if [ -n "$CENTRAL_CA_CERT" ]; then
  CENTRAL_CURL_CA=(--cacert "$CENTRAL_CA_CERT")
fi

# 2. Check Prerequisites
echo -e "${BLUE}==========================================================${NC}"
echo -e "${BLUE}        PALANTIR Remote Endpoint Auto-Installer           ${NC}"
echo -e "${BLUE}==========================================================${NC}"

if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] Docker is not installed on this system.${NC}"
  echo "Please install Docker first: https://docs.docker.com/engine/install/"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] curl is not installed on this system.${NC}"
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo -e "${RED}[ERROR] Docker Compose v2 is required for the agent bundle.${NC}"
  exit 1
fi

# 3. Auto-Detect Host Information
if [ -z "$NODE_HOSTNAME" ]; then
  NODE_HOSTNAME="$(hostname -s 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "remote-node")"
fi
# Sanitize hostname to valid RFC 1123 characters
NODE_HOSTNAME=$(echo "$NODE_HOSTNAME" | tr -cd 'a-zA-Z0-9.-' | cut -c1-63)
[ -n "$NODE_HOSTNAME" ] || NODE_HOSTNAME="remote-node"

if [ -z "$NODE_IP" ]; then
  # Extract server host/IP
  SERVER_HOST=$(echo "$SERVER_URL" | sed -E 's|^https?://||; s|:[0-9]+/?$||; s|/.*$||')
  # 1. Ask kernel which source IP is used to route to the central PALANTIR server:
  if [ -n "$SERVER_HOST" ] && [[ ! "$SERVER_HOST" =~ [^a-zA-Z0-9.-] ]]; then
    NODE_IP=$(ip -4 route get "$SERVER_HOST" 2>/dev/null | grep -oP 'src \K\S+' || true)
  fi
  # 2. Fallbacks:
  if [ -z "$NODE_IP" ]; then
    NODE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || \
              hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  fi
fi

if [[ "$NODE_IP" =~ ^10\.0\.2\. ]]; then
  echo -e "${YELLOW}[NOTICE] Detected VirtualBox NAT IP (${NODE_IP}). In standard NAT mode, the host cannot initiate inbound connections to this VM.${NC}"
  echo -e "${YELLOW}         If registration fails, consider either:${NC}"
  echo -e "${YELLOW}           1. VirtualBox Network: change adapter to 'Bridged Adapter', or${NC}"
  echo -e "${YELLOW}           2. VirtualBox NAT Port Forwarding: forward host port (e.g. 19998) to guest 19999 and run with --ip <HOST_IP> --port 19998${NC}"
  echo ""
fi

echo -e "Target Server:    ${GREEN}${SERVER_URL}${NC}"
echo -e "Node Hostname:    ${GREEN}${NODE_HOSTNAME}${NC}"
echo -e "Advertised IP:    ${GREEN}${NODE_IP}${NC}"
echo -e "Sensor Port:      ${GREEN}${PORT}${NC}"
echo -e "Sensor Image:     ${GREEN}${DOCKER_IMAGE}${NC}"
echo ""

# 4. Verify Connectivity to Central PALANTIR Server
echo -e "${YELLOW}[1/4] Probing central PALANTIR server at ${SERVER_URL}/healthz...${NC}"
if ! curl "${CENTRAL_CURL_CA[@]}" -sf --connect-timeout 5 "${SERVER_URL}/healthz" >/dev/null 2>&1; then
  echo -e "${YELLOW}[WARN] Central server at ${SERVER_URL} is not currently responding.${NC}"
  echo -e "Proceeding with sensor deployment; auto-registration will retry or can be run later."
else
  echo -e "${GREEN}[OK] Central PALANTIR server is online and reachable.${NC}"
fi

# 5. Fetch the Compose deployment definition. No repository checkout or
# hand-edited Compose file is required on the monitored endpoint.
mkdir -p "$INSTALL_DIR"
if [ -n "$CENTRAL_CA_CERT" ]; then
  install -m 0644 "$CENTRAL_CA_CERT" "${INSTALL_DIR}/central-ca.crt"
  AGENT_CA_CERT="/etc/ssl/certs/palantir-central-ca.crt"
else
  : > "${INSTALL_DIR}/central-ca.crt"
  chmod 0644 "${INSTALL_DIR}/central-ca.crt"
  AGENT_CA_CERT=""
fi
RAW_BASE="${PALANTIR_AGENT_RAW_BASE:-https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetry_pipeline}"
curl -fsSL "${RAW_BASE}/docker-compose.agent.yml" -o "${INSTALL_DIR}/docker-compose.agent.yml"

if [[ ! "$SECRET" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo -e "${RED}[ERROR] --secret must contain only letters, digits, dot, underscore, or hyphen.${NC}"
  exit 1
fi
if [[ ${#SECRET} -lt 32 ]]; then
  echo -e "${RED}[ERROR] --secret must be at least 32 characters.${NC}"
  exit 1
fi
if [[ -n "$AGENT_TOKEN" && ! "$AGENT_TOKEN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo -e "${RED}[ERROR] --token must contain only letters, digits, dot, underscore, or hyphen.${NC}"
  exit 1
fi
if [[ -n "$ENROLL_TOKEN" && ! "$ENROLL_TOKEN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo -e "${RED}[ERROR] --enrollment-token must contain only letters, digits, dot, underscore, or hyphen.${NC}"
  exit 1
fi
if [[ -n "$ENROLL_TOKEN" && ${#ENROLL_TOKEN} -lt 32 ]]; then
  echo -e "${RED}[ERROR] --enrollment-token must be at least 32 characters.${NC}"
  exit 1
fi

cat > "${INSTALL_DIR}/.env" <<EOF
PALANTIR_SERVER_URL=${SERVER_URL}
NODE_HOSTNAME=${NODE_HOSTNAME}
NODE_ADVERTISED_URL=http://${NODE_IP}:${PORT}
COLLECTOR_ADVERTISED_URL=http://${NODE_IP}:${COLLECTOR_PORT}
NETDATA_PORT=${PORT}
COLLECTOR_PORT=${COLLECTOR_PORT}
PALANTIR_WEBHOOK_SECRET=${SECRET}
PALANTIR_AGENT_TOKEN=${AGENT_TOKEN}
PALANTIR_API_ENROLL_TOKEN=${ENROLL_TOKEN}
PALANTIR_CA_CERT=${AGENT_CA_CERT}
PALANTIR_NETDATA_IMAGE=${DOCKER_IMAGE}
PALANTIR_COLLECTOR_IMAGE=${COLLECTOR_IMAGE}
EOF
chmod 600 "${INSTALL_DIR}/.env"

if docker ps -a --format '{{.Names}}' | grep -Eq '^palantir-agent$'; then
  echo -e "${YELLOW}[INFO] Removing the previous single-container PALANTIR agent.${NC}"
  docker rm -f palantir-agent >/dev/null 2>&1 || true
fi

echo -e "${YELLOW}[2/4] Pulling the Netdata and PALANTIR collector images...${NC}"
"${COMPOSE[@]}" --env-file "${INSTALL_DIR}/.env" -f "${INSTALL_DIR}/docker-compose.agent.yml" pull sensor collector

echo -e "${YELLOW}[3/4] Starting the Compose agent bundle...${NC}"
"${COMPOSE[@]}" --env-file "${INSTALL_DIR}/.env" -f "${INSTALL_DIR}/docker-compose.agent.yml" up -d

echo -e "${YELLOW}[4/4] Waiting for both host endpoints...${NC}"
MAX_TRIES=40
TRIES=0
while [ "$TRIES" -lt "$MAX_TRIES" ]; do
  if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/api/v1/info" >/dev/null 2>&1 \
    && curl -sf --max-time 2 "http://127.0.0.1:${COLLECTOR_PORT}/healthz" >/dev/null 2>&1; then
    echo -e "${GREEN}[OK] Netdata and PALANTIR host collector are healthy.${NC}"
    break
  fi
  TRIES=$((TRIES + 1))
  sleep 2
done
if [ "$TRIES" -eq "$MAX_TRIES" ]; then
  echo -e "${RED}[ERROR] Agent bundle did not become healthy.${NC}"
  echo "Inspect with: ${COMPOSE[*]} -f ${INSTALL_DIR}/docker-compose.agent.yml logs"
  exit 1
fi

if [ -z "$ENROLL_TOKEN" ]; then
  echo -e "${YELLOW}[INFO] No enrollment token supplied; automatic registration was skipped.${NC}"
  echo "Register this endpoint later from the central host with scripts/register-node.sh and an admin token."
else
  echo -e "${YELLOW}Waiting for automatic central enrollment...${NC}"
  ENROLL_TRIES=0
  ENROLL_MAX_TRIES=30
  ENROLLED=false
  while [ "$ENROLL_TRIES" -lt "$ENROLL_MAX_TRIES" ]; do
    ENROLLER_STATE=$(docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' palantir-agent-enroller 2>/dev/null || true)
    if [ "$ENROLLER_STATE" = "exited:0" ]; then
      ENROLLED=true
      break
    fi
    ENROLL_TRIES=$((ENROLL_TRIES + 1))
    sleep 2
  done
  if [ "$ENROLLED" = true ]; then
    echo -e "${GREEN}[OK] Node enrollment succeeded.${NC}"
  else
    echo -e "${YELLOW}[WARN] The agent is healthy, but central enrollment has not completed yet.${NC}"
    echo "The enroller will retry. Check with: docker logs palantir-agent-enroller"
  fi
fi

echo -e "${GREEN}Agent deployed. Netdata and the host collector are running.${NC}"
echo "Netdata:   http://${NODE_IP}:${PORT}"
echo "Collector: http://${NODE_IP}:${COLLECTOR_PORT}"
echo "Manage it with: ${COMPOSE[*]} --env-file ${INSTALL_DIR}/.env -f ${INSTALL_DIR}/docker-compose.agent.yml ps"
