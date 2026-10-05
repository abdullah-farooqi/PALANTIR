#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR — Central Platform Node Registration & Auto-Discovery Script
#
# Run this script directly on the PALANTIR Central Platform (or any machine)
# to register local or remote endpoints with zero manual guesswork.
#
# Features:
#   - Auto-detects local host IP, hostname, and Netdata sensor
#   - Auto-queries remote Netdata sensors to extract genuine hostname and OS
#   - Validates sensor connectivity before attempting registration
#   - Prevents invalid placeholder syntax (e.g. <REMOTE_ENDPOINT_IP>)
#   - Colorized diagnostic output and status checks
#
# Usage:
#   # 1. Register the local machine/server:
#   ./scripts/register-node.sh --local
#
#   # 2. Register a remote endpoint (auto-fetches remote hostname & OS):
#   ./scripts/register-node.sh 192.168.18.50
#   ./scripts/register-node.sh --target 192.168.18.50 --port 19999
#
#   # 3. Specify custom PALANTIR central server URL (if not localhost):
#   ./scripts/register-node.sh 192.168.18.50 --server http://192.168.18.43:8000
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Visual formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

SERVER_URL="${PALANTIR_SERVER_URL:-http://127.0.0.1:8000}"
API_TOKEN="${PALANTIR_API_ADMIN_TOKEN:-${PALANTIR_API_ENROLL_TOKEN:-}}"
TARGET_HOST=""
TARGET_PORT="19999"
COLLECTOR_PORT="20000"
CUSTOM_HOSTNAME=""
OS_TYPE="linux"
IS_LOCAL=false

show_help() {
  echo -e "${BOLD}PALANTIR Node Registration Utility${NC}"
  echo ""
  echo -e "${BOLD}USAGE:${NC}"
  echo "  $0 [TARGET_IP] [OPTIONS]"
  echo "  $0 --local [OPTIONS]"
  echo ""
  echo -e "${BOLD}OPTIONS:${NC}"
  echo "  --local             Automatically detect and register the local central machine"
  echo "  --target <HOST/IP>  Target endpoint IP or hostname running Netdata"
  echo "  --port <PORT>       Netdata sensor port (default: 19999)"
  echo "  --collector-port <PORT> PALANTIR collector port (default: 20000)"
  echo "  --server <URL>      PALANTIR server URL (default: http://127.0.0.1:8000 or \$PALANTIR_SERVER_URL)"
  echo "  --hostname <NAME>   Override auto-detected hostname"
  echo "  --os <OS>           Operating system type: linux, windows (default: linux)"
  echo "  -h, --help          Show this help message"
  echo ""
  echo -e "${BOLD}EXAMPLES:${NC}"
  echo "  $0 --local"
  echo "  $0 192.168.18.50"
  echo "  $0 192.168.18.50 --port 19999"
  echo "  $0 --target 172.15.80.252 --hostname fedora-prod"
  exit 0
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --local)
      IS_LOCAL=true
      shift
      ;;
    --target)
      TARGET_HOST="$2"
      shift 2
      ;;
    --port)
      TARGET_PORT="$2"
      shift 2
      ;;
    --collector-port)
      COLLECTOR_PORT="$2"
      shift 2
      ;;
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --hostname)
      CUSTOM_HOSTNAME="$2"
      shift 2
      ;;
    --os)
      OS_TYPE="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      ;;
    *)
      if [[ -z "$TARGET_HOST" && ! "$1" =~ ^- ]]; then
        TARGET_HOST="$1"
        shift
      else
        echo -e "${RED}[ERROR] Unknown option or duplicate target: $1${NC}"
        show_help
      fi
      ;;
  esac
done

SERVER_URL="${SERVER_URL%/}"
SERVER_HOST_PART="${SERVER_URL#*://}"
SERVER_HOST_PART="${SERVER_HOST_PART%%/*}"
IS_LOOPBACK_HTTP=false
case "$SERVER_HOST_PART" in
  localhost|localhost:*|127.0.0.1|127.0.0.1:*|\[::1\]|\[::1\]:*)
    if [[ "$SERVER_URL" == http://* ]]; then
      IS_LOOPBACK_HTTP=true
    fi
    ;;
esac
if [ -n "$API_TOKEN" ] && [[ "$SERVER_URL" != https://* ]] && [ "$IS_LOOPBACK_HTTP" != true ]; then
  echo -e "${RED}[ERROR] Use an HTTPS PALANTIR server URL when sending an API token.${NC}"
  exit 1
fi

echo -e "${BLUE}==========================================================${NC}"
echo -e "${BLUE}${BOLD}        PALANTIR Central Platform Node Enroller          ${NC}"
echo -e "${BLUE}==========================================================${NC}"

# Check curl prerequisite
if ! command -v curl >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] 'curl' is required but not installed.${NC}"
  exit 1
fi

# Step 1: Verify Central PALANTIR Server Reachability
echo -e "${YELLOW}[1/4] Verifying central PALANTIR API at ${SERVER_URL}...${NC}"
if ! curl -sf --connect-timeout 3 "${SERVER_URL}/healthz" >/dev/null 2>&1; then
  echo -e "${RED}[ERROR] Could not connect to PALANTIR central API at ${SERVER_URL}/healthz.${NC}"
  echo -e "Make sure the backend container is running: docker ps | grep palantir-backend"
  exit 1
fi
echo -e "${GREEN}[OK] Central PALANTIR API is online.${NC}"

# Step 2: Determine Target Sensor URL & Parameters
if [ "$IS_LOCAL" = true ] || [ -z "$TARGET_HOST" ]; then
  if [ -z "$TARGET_HOST" ] && [ "$IS_LOCAL" = false ]; then
    echo -e "${YELLOW}[INFO] No target IP provided; defaulting to local node enrollment.${NC}"
    IS_LOCAL=true
  fi

  echo -e "${YELLOW}[2/4] Auto-detecting local node network identity...${NC}"

  # Auto-detect primary routable IP (skip loopback, docker0, virbr)
  PRIMARY_LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || \
                     ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || \
                     hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

  # Probe the host-published loopback port, but give the backend the Compose
  # service DNS name so its container can reach Netdata without a host port.
  SENSOR_PROBE_URL="http://127.0.0.1:${TARGET_PORT}"
  if curl -sf --connect-timeout 2 "${SENSOR_PROBE_URL}/api/v1/info" >/dev/null 2>&1; then
    FINAL_SENSOR_URL="http://netdata:${TARGET_PORT}"
  else
    FINAL_SENSOR_URL="http://${PRIMARY_LOCAL_IP}:${TARGET_PORT}"
    SENSOR_PROBE_URL="$FINAL_SENSOR_URL"
  fi
  DEFAULT_NAME="$(hostname -s 2>/dev/null || echo "central-server")"
else
  # Remote target specified
  # Validate target host format (reject angle bracket placeholders)
  if [[ "$TARGET_HOST" == *"<"* || "$TARGET_HOST" == *">"* ]]; then
    echo -e "${RED}[ERROR] Invalid target host: '${TARGET_HOST}'. Do not include angle brackets (< >).${NC}"
    exit 1
  fi

  FINAL_SENSOR_URL="http://${TARGET_HOST}:${TARGET_PORT}"
  SENSOR_PROBE_URL="$FINAL_SENSOR_URL"
  DEFAULT_NAME="$TARGET_HOST"
fi

if [ "$IS_LOCAL" = true ]; then
  PROBE_COLLECTOR_URL="http://127.0.0.1:${COLLECTOR_PORT}"
  CANDIDATE_COLLECTOR_URL="http://host.docker.internal:${COLLECTOR_PORT}"
else
  PROBE_COLLECTOR_URL="http://${TARGET_HOST}:${COLLECTOR_PORT}"
  CANDIDATE_COLLECTOR_URL="http://${TARGET_HOST}:${COLLECTOR_PORT}"
fi
FINAL_COLLECTOR_URL=""
if curl -sf --connect-timeout 2 "${PROBE_COLLECTOR_URL}/healthz" >/dev/null 2>&1; then
  FINAL_COLLECTOR_URL="$CANDIDATE_COLLECTOR_URL"
  echo -e "${GREEN}[OK] PALANTIR host collector reachable at ${FINAL_COLLECTOR_URL}.${NC}"
else
  echo -e "${YELLOW}[INFO] No PALANTIR host collector found; registering the Netdata endpoint only.${NC}"
fi

# Step 3: Probe Sensor and Fetch Remote Metadata
echo -e "${YELLOW}[3/4] Probing sensor at ${SENSOR_PROBE_URL}/api/v1/info...${NC}"
SENSOR_INFO=$(curl -sf --connect-timeout 4 --max-time 6 "${SENSOR_PROBE_URL}/api/v1/info" 2>/dev/null || true)

DETECTED_NAME=""
DETECTED_OS=""
SENSOR_VER=""

if [ -n "$SENSOR_INFO" ]; then
  # Parse metadata safely using python or grep
  if command -v python3 >/dev/null 2>&1; then
    METADATA=$(echo "$SENSOR_INFO" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    labels = d.get("host_labels", {})
    hostname = labels.get("_hostname") or (d.get("mirrored_hosts", [None])[0]) or ""
    os_name = labels.get("_os") or d.get("os_name") or "linux"
    ver = d.get("version", "unknown")
    print(f"{hostname}|{os_name}|{ver}")
except Exception:
    print("||")
' 2>/dev/null || echo "||")
    DETECTED_NAME=$(echo "$METADATA" | cut -d'|' -f1)
    DETECTED_OS=$(echo "$METADATA" | cut -d'|' -f2)
    SENSOR_VER=$(echo "$METADATA" | cut -d'|' -f3)
  fi

  echo -e "${GREEN}[OK] Sensor reachable! Netdata Version: ${SENSOR_VER:-unknown}${NC}"
else
  echo -e "${YELLOW}[WARN] Sensor at ${FINAL_SENSOR_URL} is not responding right now.${NC}"
  echo -e "       (Enrollment will proceed, but metrics collection will wait until sensor comes online)."
fi

# Determine final node attributes
NODE_NAME="${CUSTOM_HOSTNAME:-${DETECTED_NAME:-$DEFAULT_NAME}}"
# Sanitize hostname to RFC 1123
NODE_NAME=$(echo "$NODE_NAME" | tr -cd 'a-zA-Z0-9.-' | cut -c1-63)
[ -z "$NODE_NAME" ] && NODE_NAME="monitored-node"

FINAL_OS="${DETECTED_OS:-$OS_TYPE}"
[[ "$FINAL_OS" != "windows" ]] && FINAL_OS="linux"

echo ""
echo -e "  • ${BOLD}Node Hostname:${NC}   ${GREEN}${NODE_NAME}${NC}"
echo -e "  • ${BOLD}Netdata URL:${NC}     ${GREEN}${FINAL_SENSOR_URL}${NC}"
echo -e "  • ${BOLD}OS Type:${NC}         ${GREEN}${FINAL_OS}${NC}"
echo -e "  • ${BOLD}PALANTIR Server:${NC} ${GREEN}${SERVER_URL}${NC}"
echo ""

# Step 4: Register with Central PALANTIR Database
echo -e "${YELLOW}[4/4] Submitting node enrollment to PALANTIR API...${NC}"

if [ -n "$FINAL_COLLECTOR_URL" ]; then
  PAYLOAD=$(cat <<EOF
{
  "hostname": "$NODE_NAME",
  "netdata_url": "$FINAL_SENSOR_URL",
  "collector_url": "$FINAL_COLLECTOR_URL",
  "os_type": "$FINAL_OS"
}
EOF
)
else
  PAYLOAD=$(cat <<EOF
{
  "hostname": "$NODE_NAME",
  "netdata_url": "$FINAL_SENSOR_URL",
  "os_type": "$FINAL_OS"
}
EOF
)
fi

AUTH_HEADER=()
if [ -n "$API_TOKEN" ]; then
  AUTH_HEADER=(-H "Authorization: Bearer ${API_TOKEN}")
fi
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "${SERVER_URL}/api/v1/nodes" \
  "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

if [ "$HTTP_STATUS" -eq 201 ]; then
  echo -e "${GREEN}${BOLD}✓ Node enrolled successfully!${NC}"
  echo -e "Details: ${BODY}"
  echo ""
  echo -e "${GREEN}Telemetry ingestion will automatically begin within 60 seconds.${NC}"
  exit 0
elif [ "$HTTP_STATUS" -eq 409 ]; then
  echo -e "${RED}[ERROR] Registration conflicted with an existing node or URL.${NC}"
  echo -e "Response: ${BODY}"
  exit 1
else
  echo -e "${RED}[ERROR] Enrollment failed with HTTP Status ${HTTP_STATUS}:${NC}"
  echo -e "$BODY"
  exit 1
fi
