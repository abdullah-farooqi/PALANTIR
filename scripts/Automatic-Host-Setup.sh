#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR Automatic Host Setup Script (Automatic-Host-Setup.sh)
#
# Configures a target host machine to stream telemetry data to PALANTIR Master.
# Run on any remote/local host machine — NO repo cloning or backend code required!
#
# Works on bare-metal servers, VM hosts (libvirt / Proxmox / LXD / QEMU) and plain
# virtual machines / cloud instances. Optional data sources (Docker, Podman, LXD,
# libvirt ...) are detected on this host, so nothing is mounted that does not exist.
#
# Optional environment variables:
#   PALANTIR_AGENT_TOKEN   skip the access question and use this token (master's AGENT_AUTH_TOKEN)
#   COLLECTOR_IMAGE        use another image (e.g. a locally built one)
#   PROXMOX_API_URL / PROXMOX_API_TOKEN / PROXMOX_INSECURE_TLS=1   Proxmox API (full VM metrics)
#   KUBERNETES_API_URL / KUBERNETES_TOKEN                          Kubernetes pod metrics
#   DRY_RUN=1              only print the docker command
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DRY_RUN="${DRY_RUN:-0}"
AGENT_TOKEN="${PALANTIR_AGENT_TOKEN:-}"

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}     PALANTIR Automatic Target Host Setup Script     ${NC}"
echo -e "${CYAN}=====================================================${NC}"

# 1. Require Root / Sudo
if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" != "1" ]; then
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

# 3. Detect System Environment & Enable Kernel IPv4 Forwarding
IS_VM=0
SYS_TYPE="Physical Bare-Metal Host"
if command -v systemd-detect-virt &>/dev/null && systemd-detect-virt -q; then
  IS_VM=1
  SYS_TYPE="Virtual Machine ($(systemd-detect-virt))"
else
  DMI_PROD=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
  DMI_VEND=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
  if echo "$DMI_PROD $DMI_VEND" | grep -qiE "kvm|qemu|virtualbox|innotek|vmware|virtual machine"; then
    IS_VM=1
    SYS_TYPE="Virtual Machine (${DMI_PROD:-KVM})"
  elif [ -n "$DMI_PROD" ]; then
    SYS_TYPE="Physical Host ($DMI_VEND $DMI_PROD)"
  fi
fi

# Automatically enable IPv4 forwarding (safe on both hosts & VMs, enables cross-network NAT routing)
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [ -d /etc/sysctl.d ]; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-palantir-forward.conf 2>/dev/null || true
  fi
fi

# If this physical host runs KVM/libvirt VMs (virbr0), allow forwarded traffic to guest VMs
if [ "$IS_VM" = "0" ] && ip link show virbr0 &>/dev/null; then
  iptables -I FORWARD -o virbr0 -p tcp --dport 20000 -j ACCEPT 2>/dev/null || true
  iptables -I FORWARD -i virbr0 -j ACCEPT 2>/dev/null || true
fi

# 4. Stop & Clean any existing collector containers first
if [ "$DRY_RUN" != "1" ]; then
  echo -e "${CYAN}Cleaning any existing PALANTIR host containers...${NC}"
  docker rm -f palantir-collector 2>/dev/null || true
  docker ps -q --filter "publish=20000" | xargs -r docker rm -f 2>/dev/null || true
  sleep 1
fi

# 5. Check and Handle Occupied Port (20000)
check_port() {
  local port=$1
  local name=$2

  if lsof -i :$port &> /dev/null || netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
    echo -e "${YELLOW}WARNING: Port $port ($name) is currently in use!${NC}"
    echo -e "Choose an option:"
    echo "  [1] Automatically terminate process on port $port and proceed (Recommended)"
    echo "  [2] Quit setup"
    echo "Select option [1/2] (default 1): "
    read -r choice || choice="1"
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

[ "$DRY_RUN" = "1" ] || check_port 20000 "Palantir Hardware Collector"

# 5. Handle Firewall (UFW / firewalld)
if [ "$DRY_RUN" != "1" ]; then
  if command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
      echo -e "${YELLOW}UFW Firewall detected. Opening port 20000...${NC}"
      ufw allow 20000/tcp >/dev/null
      echo -e "${GREEN}✓ Firewall port 20000 opened.${NC}"
    fi
  fi
  if command -v firewall-cmd &> /dev/null && firewall-cmd --state &> /dev/null; then
    echo -e "${YELLOW}firewalld detected. Opening port 20000...${NC}"
    firewall-cmd --permanent --add-port=20000/tcp >/dev/null && firewall-cmd --reload >/dev/null
    echo -e "${GREEN}✓ Firewall port 20000 opened.${NC}"
  fi
fi

# 6. Check and Pull Latest Palantir Host Collector Image
if [ -z "${COLLECTOR_IMAGE:-}" ] && docker image inspect palantir-host-collector:local &>/dev/null; then
  COLLECTOR_IMAGE="palantir-host-collector:local"
  echo -e "${GREEN}✓ Using locally built collector image: ${COLLECTOR_IMAGE}${NC}"
else
  COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-abdullahahmadfarooqi/palantir-host-collector:latest}"
  if [ "$DRY_RUN" != "1" ]; then
    echo -e "${CYAN}Checking for collector image updates (${COLLECTOR_IMAGE})...${NC}"
    if PULL_OUTPUT=$(docker pull "${COLLECTOR_IMAGE}" 2>&1); then
      if echo "$PULL_OUTPUT" | grep -iq "Status: Image is up to date"; then
        echo -e "${GREEN}✓ Image is already up to date. Using existing local image.${NC}"
      else
        echo -e "${GREEN}✓ Downloaded updated image layers for ${COLLECTOR_IMAGE}.${NC}"
      fi
    elif docker image inspect "${COLLECTOR_IMAGE}" &> /dev/null; then
      echo -e "${YELLOW}WARNING: Could not pull ${COLLECTOR_IMAGE}; using the image already on this host.${NC}"
    else
      echo -e "${RED}ERROR: Could not pull ${COLLECTOR_IMAGE} and no local copy exists:${NC}"
      echo "$PULL_OUTPUT"
      exit 1
    fi
  fi
fi

# 6b. Who is allowed to talk to / control this host's collector?
#     master  = only the PALANTIR master (it must present the shared AGENT_AUTH_TOKEN)
#     anyone  = no token: anybody who can reach port 20000 can read data AND kill processes
#     readonly= no token and no tty to ask on: reads open, process control disabled
TTY_DEV="${PALANTIR_TTY:-/dev/tty}"
ACCESS_MODE=""

valid_token() { [[ "$1" =~ ^[A-Za-z0-9._-]{32,}$ ]]; }

configure_access() {
  if [ -n "$AGENT_TOKEN" ]; then
    valid_token "$AGENT_TOKEN" || { echo -e "${RED}ERROR: PALANTIR_AGENT_TOKEN must be at least 32 characters (letters, digits, . _ -).${NC}"; exit 1; }
    ACCESS_MODE="master"; return
  fi

  echo -e "\n${CYAN}Who should be allowed to control this host (read data, kill processes, stop containers & VMs)?${NC}"
  echo "  [1] Only my PALANTIR master server  (asks for the master's AGENT_AUTH_TOKEN)  - Recommended"
  echo "  [2] Anyone who can reach this host  (no token: anybody on the network can read data and execute controls)"
  echo "Select option [1/2] (default 1): "
  read -r choice || choice="1"

  if [ "$choice" = "2" ]; then
    echo -e "${YELLOW}WARNING: with no token, anyone who can reach port 20000 can read this host's data, kill processes, and stop containers/VMs.${NC}"
    echo "Type YES to confirm: "
    read -r confirm || confirm=""
    if [ "$confirm" = "YES" ]; then
      ACCESS_MODE="anyone"; return
    fi
    echo -e "${YELLOW}Not confirmed - using the master-only option instead.${NC}"
  fi

  local attempt
  for attempt in 1 2 3; do
    echo "Enter the master's AGENT_AUTH_TOKEN (hidden, same value as on the master server): "
    read -r -s AGENT_TOKEN || AGENT_TOKEN=""
    echo
    if valid_token "$AGENT_TOKEN"; then ACCESS_MODE="master"; return; fi
    echo -e "${RED}Invalid token: it must be at least 32 characters (letters, digits, . _ -).${NC}"
  done
  echo -e "${RED}No valid token entered. Setup aborted.${NC}"
  exit 1
}

configure_access

# 7. Detect which optional data sources this host has
#    (a missing bind-mount source would be created as an empty directory, so only real ones are used)
EXTRA_ENV=()
SOURCES_FOUND=()

if [ -S /run/docker.sock ] || [ -S /var/run/docker.sock ]; then
  EXTRA_ENV+=(-e DOCKER_SOCKET=/host/run/docker.sock); SOURCES_FOUND+=("Docker containers")
elif [ -S /run/podman/podman.sock ]; then
  EXTRA_ENV+=(-e DOCKER_SOCKET=/host/run/podman/podman.sock); SOURCES_FOUND+=("Podman containers")
fi

if [ -S /var/snap/lxd/common/lxd/unix.socket ]; then
  EXTRA_ENV+=(-e LXD_SOCKET=/host/var/snap/lxd/common/lxd/unix.socket); SOURCES_FOUND+=("LXD (snap)")
elif [ -S /var/lib/lxd/unix.socket ]; then
  EXTRA_ENV+=(-e LXD_SOCKET=/host/var/lib/lxd/unix.socket); SOURCES_FOUND+=("LXD")
elif [ -S /var/lib/incus/unix.socket ]; then
  EXTRA_ENV+=(-e LXD_SOCKET=/host/var/lib/incus/unix.socket); SOURCES_FOUND+=("Incus")
fi

if [ -S /run/libvirt/libvirt-sock ]; then
  SOURCES_FOUND+=("libvirt VMs")
elif [ -S /run/libvirt/virtqemud-sock ]; then
  EXTRA_ENV+=(-e LIBVIRT_SOCKET=/host/run/libvirt/virtqemud-sock); SOURCES_FOUND+=("libvirt VMs (modular daemon)")
fi
[ -d /var/lib/lxc ] && SOURCES_FOUND+=("LXC containers")
if pgrep -f 'qemu-system|/kvm |qemu-kvm' &> /dev/null; then
  SOURCES_FOUND+=("QEMU/KVM guests (Proxmox / plain QEMU)")
fi
[ -S /run/dbus/system_bus_socket ] && SOURCES_FOUND+=("systemd services")
{ [ -d /var/log/journal ] || [ -d /run/log/journal ]; } && SOURCES_FOUND+=("journal logs")

# Kubernetes auto-detection (K3s, MicroK8s, kubeadm, or kubelet)
if [ -f /etc/rancher/k3s/k3s.yaml ]; then
  SOURCES_FOUND+=("Kubernetes (K3s)")
  EXTRA_ENV+=(-e KUBERNETES_API_URL=https://127.0.0.1:6443)
  K3S_TOKEN=$(grep -E "^\s*token:" /etc/rancher/k3s/k3s.yaml 2>/dev/null | awk '{print $2}' || true)
  [ -z "$K3S_TOKEN" ] || EXTRA_ENV+=(-e "KUBERNETES_TOKEN=${K3S_TOKEN}")
elif [ -f /etc/kubernetes/admin.conf ]; then
  SOURCES_FOUND+=("Kubernetes (admin.conf)")
  K8S_SERVER=$(grep -E "^\s*server:" /etc/kubernetes/admin.conf 2>/dev/null | head -n1 | awk '{print $2}' || true)
  [ -z "$K8S_SERVER" ] || EXTRA_ENV+=(-e "KUBERNETES_API_URL=${K8S_SERVER}")
elif [ -f /var/snap/microk8s/current/credentials/client.config ]; then
  SOURCES_FOUND+=("Kubernetes (MicroK8s)")
elif pgrep -f 'kubelet|k3s|microk8s' &>/dev/null; then
  SOURCES_FOUND+=("Kubernetes (kubelet active)")
fi

[ -z "$AGENT_TOKEN" ] || EXTRA_ENV+=(-e "PALANTIR_AGENT_TOKEN=${AGENT_TOKEN}")
[ "$ACCESS_MODE" != "anyone" ] || EXTRA_ENV+=(-e PALANTIR_ALLOW_ANON_KILL=1)
for var in PROXMOX_API_URL PROXMOX_API_TOKEN PROXMOX_CA_CERT PROXMOX_INSECURE_TLS KUBERNETES_API_URL KUBERNETES_TOKEN KUBERNETES_CA_CERT; do
  if [ -n "${!var:-}" ]; then
    EXTRA_ENV+=(-e "$var=${!var}")
    case "$var" in PROXMOX_API_URL) SOURCES_FOUND+=("Proxmox API");; KUBERNETES_API_URL) SOURCES_FOUND+=("Kubernetes API");; esac
  fi
done

# SELinux (Fedora / RHEL / Rocky): containers cannot read host files unless label separation is off
SECURITY_OPTS=(--security-opt apparmor=unconfined)
if command -v getenforce &> /dev/null && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
  SECURITY_OPTS+=(--security-opt label=disable)
fi

# 8. Deploy Palantir Host Hardware Collector (Port 20000)
#    /:/host:ro,rslave  = the whole host tree read-only (disks, /proc, /sys, /run sockets, /etc, logs)
#    --net=host --pid=host = real host interfaces, sockets and per-process data
#    SYS_PTRACE = read every process' fds / mounts / network;  NET_ADMIN = read the firewall ruleset
build_run_args() {
  RUN_ARGS=(run -d
    --name palantir-collector
    --restart unless-stopped
    --net=host --pid=host
    --cap-add SYS_PTRACE --cap-add NET_ADMIN
    "${SECURITY_OPTS[@]}"
    -v "/:/host:ro${1}"
    -v palantir-collector-state:/var/lib/palantir-agent
    -e HOST_PROC=/host/proc -e HOST_SYS=/host/sys -e HOST_ROOT=/host -e HOST_LOG=/host/var/log
    -e HOME=/tmp
    "${EXTRA_ENV[@]}"
    "${COLLECTOR_IMAGE}")
}

if [ "$DRY_RUN" = "1" ]; then
  build_run_args ",rslave"
  printf 'docker'; printf ' %q' "${RUN_ARGS[@]}"; echo
  exit 0
fi

echo -e "${CYAN}Deploying Palantir Hardware Collector (Port 20000)...${NC}"
build_run_args ",rslave"
if ! RUN_OUTPUT=$(docker "${RUN_ARGS[@]}" 2>&1); then
  if echo "$RUN_OUTPUT" | grep -qi "shared or slave"; then
    echo -e "${YELLOW}Root mount is not shared on this host; using a plain read-only mount.${NC}"
    docker rm -f palantir-collector &> /dev/null || true
    build_run_args ""
    docker "${RUN_ARGS[@]}" > /dev/null
  else
    echo -e "${RED}ERROR: could not start the collector:${NC}\n${RUN_OUTPUT}"
    exit 1
  fi
fi

# 9. Wait until the collector answers
HEALTHY=0
for _ in $(seq 1 25); do
  if curl -fsS --max-time 2 http://127.0.0.1:20000/healthz &> /dev/null; then HEALTHY=1; break; fi
  sleep 1
done

# 10. Determine Host IP (Detecting Ethernet / Wi-Fi)
GET_IP() {
  local ip=""
  # Source address of the route to the internet (field after "src")
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
  if [ -z "$ip" ]; then
    # Fallback to hostname -I first IPv4
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  echo "$ip"
}

HOST_IP=$(GET_IP)
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')

echo -e "\n${GREEN}=====================================================${NC}"
if [ "$HEALTHY" = "1" ]; then
  echo -e "${GREEN}      ✓ PALANTIR HOST SETUP COMPLETED SUCCESSFULLY   ${NC}"
else
  echo -e "${YELLOW}      ! Collector started but is not answering yet    ${NC}"
  echo -e "${YELLOW}        Check: docker logs palantir-collector         ${NC}"
fi
echo -e "${GREEN}=====================================================${NC}"

echo -e "System Environment        : ${CYAN}${SYS_TYPE}${NC}"
if [ "$IS_VM" = "0" ] && ip link show virbr0 &>/dev/null; then
  echo -e "KVM Bridge Detected       : ${YELLOW}virbr0 (Subnet 192.168.122.0/24 forwarding active)${NC}"
fi
if [ -n "$IFACE" ]; then
  echo -e "Network Interface Detected: ${YELLOW}${IFACE}${NC}"
fi
echo -e "Target Host IP Address    : ${CYAN}${HOST_IP}${NC}"
if [ "$IS_VM" = "1" ] && [[ "$HOST_IP" =~ ^(192\.168\.122\.|10\.0\.2\.) ]]; then
  echo -e "${YELLOW}Note: This VM is using internal NAT subnet (${HOST_IP}).${NC}"
  echo -e "If Master Server is on a separate PC, simply run on Master Server:"
  echo -e "  ${CYAN}sudo bash scripts/Automatic-VM-Setup-For-NAT.sh${NC}"
fi
if [ ${#SOURCES_FOUND[@]} -gt 0 ]; then
  echo -e "Data sources detected     : ${CYAN}$(IFS=,; echo "${SOURCES_FOUND[*]}" | sed 's/,/, /g')${NC}"
fi
echo -e "Always collected          : CPU, memory, disks, network, processes, sockets"
case "$ACCESS_MODE" in
  master)   echo -e "Access                    : ${GREEN}only the master server (token required) - process control enabled${NC}" ;;
  anyone)   echo -e "Access                    : ${YELLOW}OPEN to anyone who can reach port 20000 (read + kill)${NC}" ;;
  readonly) echo -e "Access                    : ${YELLOW}open read-only, process control disabled (no token, no terminal to ask).${NC}"
            echo -e "${YELLOW}                            Re-run with PALANTIR_AGENT_TOKEN=<master AGENT_AUTH_TOKEN> to secure it.${NC}" ;;
esac
echo ""

echo -e "Use these details in your PALANTIR Master UI (${YELLOW}http://localhost:3000${NC}):"
echo -e "  • ${CYAN}Hostname / Label${NC}: ${YELLOW}server-01${NC} (or your machine name)"
echo -e "  • ${CYAN}Host IP Address ${NC}: ${YELLOW}${HOST_IP}${NC}"
echo -e "Troubleshooting: curl -s http://127.0.0.1:20000/api/v1/diagnostics"
echo -e "=====================================================\n"
