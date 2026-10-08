#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR Automatic Host Setup Script (Automatic-Host-Setup.sh)
#
# Configures a target host machine to stream telemetry data to PALANTIR Master.
# Run on any remote/local host machine — NO repo cloning or backend code required!
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}     PALANTIR Automatic Target Host Setup Script     ${NC}"
echo -e "${CYAN}=====================================================${NC}"

# 1. Require Root / Sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ERROR: Please run this script with sudo or as root:${NC}"
  echo -e "  sudo bash Automatic-Host-Setup.sh"
  exit 1
fi

# 2. Check Docker Installation
if ! command -v docker &> /dev/null; then
  echo -e "${RED}ERROR: Docker engine is not installed on this host.${NC}"
  echo -e "Please install Docker first: https://docs.docker.com/engine/install/"
  exit 1
fi

# 3. Stop & Clean any existing telemetry/collector containers first
echo -e "${CYAN}Cleaning any existing PALANTIR host containers...${NC}"
docker rm -f palantir-netdata palantir-collector netdata 2>/dev/null || true
docker ps -q --filter "publish=19999" | xargs -r docker rm -f 2>/dev/null || true
docker ps -q --filter "publish=20000" | xargs -r docker rm -f 2>/dev/null || true
sleep 1

# 4. Check and Handle Occupied Ports (19999 and 20000)
check_port() {
  local port=$1
  local name=$2
  
  if lsof -i :$port &> /dev/null || netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
    echo -e "${YELLOW}WARNING: Port $port ($name) is currently in use!${NC}"
    echo -e "Choose an option:"
    echo "  [1] Automatically terminate process on port $port and proceed (Recommended)"
    echo "  [2] Quit setup"
    read -r -p "Select option [1/2]: " choice < /dev/tty || choice="1"
    case "$choice" in
      1)
        echo -e "${YELLOW}Terminating process occupying port $port...${NC}"
        docker ps -q --filter "publish=${port}" | xargs -r docker rm -f 2>/dev/null || true
        fuser -k -9 ${port}/tcp 2>/dev/null || true
        pids=$(ss -tulpn "sport = :${port}" 2>/dev/null | grep -oP 'pid=\K\d+' | sort -u || true)
        if [ -n "$pids" ]; then
          echo "$pids" | xargs -r kill -9 2>/dev/null || true
        fi
        sleep 2
        ;;
      *)
        echo -e "${RED}Setup aborted by user.${NC}"
        exit 1
        ;;
    esac
  fi
}

check_port 19999 "Palantir Telemetry Sensor"
check_port 20000 "Palantir Hardware Collector"

# 5. Handle Firewall (UFW / iptables)
if command -v ufw &> /dev/null; then
  if ufw status | grep -q "Status: active"; then
    echo -e "${YELLOW}UFW Firewall detected. Opening ports 19999 & 20000...${NC}"
    ufw allow 19999/tcp >/dev/null
    ufw allow 20000/tcp >/dev/null
    echo -e "${GREEN}✓ Firewall ports 19999 & 20000 opened.${NC}"
  fi
fi

# 6. Deploy Palantir Telemetry Sensor (Port 19999)
echo -e "${CYAN}Deploying Palantir Telemetry Sensor (Port 19999)...${NC}"
docker run -d \
  --name palantir-netdata \
  -p 0.0.0.0:19999:19999 \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /etc/os-release:/host/etc/os-release:ro \
  --restart unless-stopped \
  abdullahahmadfarooqi/palantir-netdata:latest >/dev/null

# 7. Deploy Palantir Host Hardware Collector (Port 20000)
echo -e "${CYAN}Deploying Palantir Hardware Collector (Port 20000)...${NC}"
docker run -d \
  --name palantir-collector \
  -p 0.0.0.0:20000:20000 \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /etc/os-release:/host/etc/os-release:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --restart unless-stopped \
  abdullahahmadfarooqi/palantir-host-collector:latest >/dev/null

# 8. Determine Host IP (Detecting Ethernet / Wi-Fi)
GET_IP() {
  local ip=""
  # Try route to default gateway
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}')
  if [ -z "$ip" ]; then
    # Fallback to hostname -I first IPv4
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  echo "$ip"
}

HOST_IP=$(GET_IP)
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5}')

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN}      ✓ PALANTIR HOST SETUP COMPLETED SUCCESSFULLY   ${NC}"
echo -e "${GREEN}=====================================================${NC}"

if [ -n "$IFACE" ]; then
  echo -e "Network Interface Detected: ${YELLOW}${IFACE}${NC}"
fi
echo -e "Target Host IP Address    : ${CYAN}${HOST_IP}${NC}\n"

echo -e "Use these details in your PALANTIR Master UI (${YELLOW}http://localhost:3000${NC}):"
echo -e "  • ${CYAN}Hostname / Label${NC}: ${YELLOW}server-01${NC} (or your machine name)"
echo -e "  • ${CYAN}Host IP Address ${NC}: ${YELLOW}${HOST_IP}${NC}"
echo -e "=====================================================\n"
