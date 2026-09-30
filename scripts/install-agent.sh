#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR — Zero-Touch Remote Agent Installer & Enroller
#
# Run this script on ANY remote machine or VM to deploy the lightweight
# Netdata telemetry sensor and automatically register it with the PALANTIR server.
#
# Quickstart Usage:
#   curl -fsSL https://raw.githubusercontent.com/<owner>/PALANTIR/main/scripts/install-agent.sh | bash -s -- http://<SYSADMIN_IP>:8000
#
# Or run locally:
#   ./scripts/install-agent.sh http://<SYSADMIN_IP>:8000
#
# Flags:
#   --server <URL>     PALANTIR Central Server URL (e.g. http://192.168.1.50:8000)
#   --hostname <NAME>  Custom hostname for this node (default: detected hostname)
#   --ip <IP>          Custom advertised IP (default: detected primary IP)
#   --port <PORT>      Sensor port (default: 19999)
#   --secret <SECRET>  Webhook authentication secret
#   --image <IMAGE>    Custom docker image (default: abdullahahmadfarooqi/palantir-netdata:latest)
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
SECRET="palantir-super-secret-key-change-me"
DOCKER_IMAGE="abdullahahmadfarooqi/palantir-netdata:latest"

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
    --secret)
      SECRET="$2"
      shift 2
      ;;
    --image)
      DOCKER_IMAGE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 <PALANTIR_SERVER_URL> [options]"
      echo "Options:"
      echo "  --server <URL>     PALANTIR Central Server URL (e.g. http://192.168.1.50:8000)"
      echo "  --hostname <NAME>  Custom node hostname"
      echo "  --ip <IP>          Custom node advertised IP"
      echo "  --port <PORT>      Port for Netdata sensor (default: 19999)"
      echo "  --secret <SECRET>  Shared secret for webhooks"
      echo "  --image <IMAGE>    Sensor Docker image"
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

SERVER_URL="${SERVER_URL%/}" # Strip trailing slash

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

# 3. Auto-Detect Host Information
if [ -z "$NODE_HOSTNAME" ]; then
  NODE_HOSTNAME="$(hostname -s 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "remote-node")"
fi
# Sanitize hostname to valid RFC 1123 characters
NODE_HOSTNAME=$(echo "$NODE_HOSTNAME" | tr -cd 'a-zA-Z0-9.-' | cut -c1-63)

if [ -z "$NODE_IP" ]; then
  NODE_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
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
if ! curl -sf --connect-timeout 5 "${SERVER_URL}/healthz" >/dev/null 2>&1; then
  echo -e "${YELLOW}[WARN] Central server at ${SERVER_URL} is not currently responding.${NC}"
  echo -e "Proceeding with sensor deployment; auto-registration will retry or can be run later."
else
  echo -e "${GREEN}[OK] Central PALANTIR server is online and reachable.${NC}"
fi

# 5. Clean up old container if exists
if docker ps -a --format '{{.Names}}' | grep -Eq "^palantir-agent$"; then
  echo -e "${YELLOW}[2/4] Stopping existing palantir-agent container...${NC}"
  docker rm -f palantir-agent >/dev/null 2>&1 || true
fi

# 6. Launch Lightweight Sensor Container
echo -e "${YELLOW}[2/4] Starting lightweight Netdata telemetry sensor...${NC}"
docker run -d \
  --name palantir-agent \
  --restart unless-stopped \
  --pid host \
  --cap-add SYS_PTRACE \
  --cap-add SYS_ADMIN \
  --security-opt apparmor:unconfined \
  -p "${PORT}:19999" \
  -e PALANTIR_WEBHOOK_URL="${SERVER_URL}/internal/alert" \
  -e PALANTIR_WEBHOOK_SECRET="${SECRET}" \
  "${DOCKER_IMAGE}" >/dev/null

echo -e "${GREEN}[OK] Sensor container started successfully.${NC}"

# 7. Wait for Local Sensor to be Healthy
echo -e "${YELLOW}[3/4] Waiting for sensor telemetry engine to initialize...${NC}"
MAX_TRIES=20
TRIES=0
SENSOR_READY=false

while [ $TRIES -lt $MAX_TRIES ]; do
  if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/api/v1/info" >/dev/null 2>&1; then
    SENSOR_READY=true
    break
  fi
  TRIES=$((TRIES + 1))
  sleep 1
done

if [ "$SENSOR_READY" = false ]; then
  echo -e "${RED}[ERROR] Sensor failed to become ready within timeout.${NC}"
  echo "Check container logs: docker logs palantir-agent"
  exit 1
fi
echo -e "${GREEN}[OK] Local telemetry engine is active on port ${PORT}.${NC}"

# 8. Register Node with Central PALANTIR Server
echo -e "${YELLOW}[4/4] Registering node '${NODE_HOSTNAME}' with central server...${NC}"

REG_PAYLOAD=$(cat <<EOF
{
  "hostname": "$NODE_HOSTNAME",
  "netdata_url": "http://$NODE_IP:$PORT",
  "os_type": "linux"
}
EOF
)

REG_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "${SERVER_URL}/api/v1/nodes" \
  -H "Content-Type: application/json" \
  -d "$REG_PAYLOAD")

HTTP_STATUS=$(echo "$REG_RESPONSE" | grep "HTTP_STATUS" | cut -d':' -f2)
REG_BODY=$(echo "$REG_RESPONSE" | sed '/HTTP_STATUS/d')

if [ "$HTTP_STATUS" -eq 201 ]; then
  echo -e "${GREEN}[SUCCESS] Node registered successfully!${NC}"
  echo -e "Registration Details: $REG_BODY"
  echo ""
  echo -e "${GREEN}==========================================================${NC}"
  echo -e "${GREEN}✓ PALANTIR Agent successfully installed and connected!   ${NC}"
  echo -e "${GREEN}  - Telemetry streaming every 60s to: ${SERVER_URL}       ${NC}"
  echo -e "${GREEN}  - Real-time alerts configured to:   ${SERVER_URL}       ${NC}"
  echo -e "${GREEN}==========================================================${NC}"
  exit 0
else
  echo -e "${YELLOW}[WARN] Automatic enrollment returned HTTP status ${HTTP_STATUS}:${NC}"
  echo "$REG_BODY"
  echo ""
  echo -e "You can retry registration at any time with:"
  echo -e "  curl -X POST ${SERVER_URL}/api/v1/nodes -H 'Content-Type: application/json' -d '$REG_PAYLOAD'"
  exit 0
fi
