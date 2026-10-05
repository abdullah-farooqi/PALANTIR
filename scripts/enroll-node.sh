#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# PALANTIR Node Auto-Enrollment Script
# Usage:
#   ./scripts/enroll-node.sh --palantir-url http://<PALANTIR_IP>:8000
#
# Flags:
#   --palantir-url   URL of the central PALANTIR server (required)
#   --hostname       Custom hostname for this node (default: system hostname)
#   --netdata-url    Advertised Netdata URL (default: http://<detected-ip>:19999)
#   --os-type        Operating system type (default: linux)
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

PALANTIR_URL=""
HOSTNAME_VAL="$(hostname -s 2>/dev/null || echo "remote-node")"
NETDATA_URL=""
OS_TYPE="linux"
API_TOKEN="${PALANTIR_API_ENROLL_TOKEN:-${PALANTIR_API_ADMIN_TOKEN:-}}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --palantir-url)
      PALANTIR_URL="$2"
      shift 2
      ;;
    --hostname)
      HOSTNAME_VAL="$2"
      shift 2
      ;;
    --netdata-url)
      NETDATA_URL="$2"
      shift 2
      ;;
    --os-type)
      OS_TYPE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 --palantir-url <URL> [--hostname <NAME>] [--netdata-url <URL>] [--os-type <OS>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$PALANTIR_URL" ]; then
  echo "Error: --palantir-url is required (e.g., --palantir-url http://192.168.1.100:8000)"
  exit 1
fi
if [ -n "$API_TOKEN" ] && [[ "$PALANTIR_URL" != https://* ]]; then
  echo "Error: use an HTTPS PALANTIR URL when sending an API token."
  exit 1
fi

# Detect primary host IP if not provided
if [ -z "$NETDATA_URL" ]; then
  PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  NETDATA_URL="http://${PRIMARY_IP}:19999"
fi

echo "=========================================================="
echo "PALANTIR Node Enrollment"
echo "  Central Server: $PALANTIR_URL"
echo "  Node Hostname:  $HOSTNAME_VAL"
echo "  Netdata Sensor: $NETDATA_URL"
echo "  OS Type:        $OS_TYPE"
echo "=========================================================="

# 1. Probe local Netdata sensor
echo "Step 1: Checking local Netdata sensor at $NETDATA_URL/api/v1/info..."
if curl -sf --max-time 5 "$NETDATA_URL/api/v1/info" >/dev/null 2>&1; then
  echo "  ✓ Local Netdata sensor is online and reachable."
else
  echo "  ⚠ Warning: Could not reach $NETDATA_URL/api/v1/info."
  echo "  Make sure the Netdata sensor is running and port 19999 is accessible."
fi

# 2. Register node with PALANTIR parent server
echo "Step 2: Enrolling node with PALANTIR parent server..."
PAYLOAD=$(cat <<EOF
{
  "hostname": "$HOSTNAME_VAL",
  "netdata_url": "$NETDATA_URL",
  "os_type": "$OS_TYPE"
}
EOF
)

AUTH_HEADER=()
if [ -n "$API_TOKEN" ]; then
  AUTH_HEADER=(-H "Authorization: Bearer ${API_TOKEN}")
fi
SERVER_CA_ARGS=()
if [ -n "${PALANTIR_CA_CERT:-}" ]; then
  SERVER_CA_ARGS=(--cacert "$PALANTIR_CA_CERT")
fi
RESPONSE=$(curl "${SERVER_CA_ARGS[@]}" -s -w "\nHTTP_STATUS:%{http_code}" -X POST "${PALANTIR_URL}/api/v1/nodes" \
  "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

if [ "$HTTP_STATUS" -eq 201 ]; then
  echo "  ✓ Node successfully enrolled with PALANTIR parent server!"
  echo "  Registration details: $BODY"
  echo ""
  echo "PALANTIR Celery collectors will now ingest metrics every 60s and evaluate anomaly scores every 5m."
  exit 0
else
  echo "  ✗ Enrollment failed (HTTP status $HTTP_STATUS):"
  echo "  $BODY"
  exit 1
fi
