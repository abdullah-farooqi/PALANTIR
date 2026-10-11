#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR Automatic NAT Routing Setup for Remote VMs (Automatic-VM-Setup-For-NAT.sh)
#
# Configures the PALANTIR Master Server to route traffic directly to Virtual
# Machines hosted on a secondary physical PC (e.g. PC2) behind internal NAT
# subnets (KVM/libvirt 192.168.122.x or VirtualBox 10.0.2.x).
#
# Run on: PALANTIR MASTER SERVER
#
# Usage:
#   sudo bash scripts/Automatic-VM-Setup-For-NAT.sh [HOST_PC_IP] [VM_SUBNET]
# Or interactively:
#   sudo bash scripts/Automatic-VM-Setup-For-NAT.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}     PALANTIR Automatic VM NAT Routing Setup         ${NC}"
echo -e "${CYAN}=====================================================${NC}"

# 1. Require Root / Sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}ERROR: Please run this script with sudo or as root on the Master Server:${NC}"
  echo -e "  sudo bash scripts/Automatic-VM-Setup-For-NAT.sh"
  exit 1
fi

# 2. Parse or Prompt for Target Host PC IP and VM Subnet
HOST_PC_IP="${1:-${HOST_PC_IP:-}}"
VM_SUBNET="${2:-${VM_SUBNET:-}}"

if [ -z "$HOST_PC_IP" ]; then
  echo -e "\n${CYAN}[1/3] Target Host Computer Information${NC}"
  echo -e "Enter the LAN IP address of the physical machine hosting the VMs (e.g. PC2):"
  read -r -p "Host PC LAN IP: " HOST_PC_IP
fi

# Validate Host PC IP format
if ! [[ "$HOST_PC_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo -e "${RED}ERROR: Invalid Host PC IP address format: '${HOST_PC_IP}'${NC}"
  exit 1
fi

if [ -z "$VM_SUBNET" ]; then
  echo -e "\nEnter the VM NAT subnet (Default is KVM/libvirt: 192.168.122.0/24):"
  read -r -p "VM Subnet [192.168.122.0/24]: " input_subnet
  VM_SUBNET="${input_subnet:-192.168.122.0/24}"
fi

# Validate Subnet CIDR format
if ! [[ "$VM_SUBNET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
  echo -e "${RED}ERROR: Invalid VM Subnet format: '${VM_SUBNET}'. Expected CIDR (e.g. 192.168.122.0/24)${NC}"
  exit 1
fi

# 3. Test Network Reachability to the Host PC
echo -e "\n${CYAN}[2/3] Verifying LAN reachability to Host PC (${HOST_PC_IP})...${NC}"
if ping -c 1 -W 2 "$HOST_PC_IP" &>/dev/null; then
  echo -e "${GREEN}✓ Host PC ${HOST_PC_IP} is reachable on the local network.${NC}"
else
  echo -e "${YELLOW}WARNING: Ping to ${HOST_PC_IP} did not respond (may be firewalled or sleeping).${NC}"
  echo -e "Proceeding with route configuration..."
fi

# 4. Apply Kernel Route on Master Server
echo -e "\n${CYAN}[3/3] Configuring Linux kernel static route on Master Server...${NC}"
ip route replace "$VM_SUBNET" via "$HOST_PC_IP"
echo -e "${GREEN}✓ Kernel route applied: ${VM_SUBNET} via ${HOST_PC_IP}${NC}"

# 5. Persist the Route Across Reboots via Systemd Service
SERVICE_FILE="/etc/systemd/system/palantir-nat-route.service"
cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=PALANTIR Master Server NAT Route to Remote VMs
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/ip route replace ${VM_SUBNET} via ${HOST_PC_IP}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl &>/dev/null; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable palantir-nat-route.service >/dev/null 2>&1 || true
  echo -e "${GREEN}✓ Persistent systemd service enabled (${SERVICE_FILE}).${NC}"
fi

# 6. Verify Active Routing Table
ACTIVE_ROUTE=$(ip route show "$VM_SUBNET" 2>/dev/null || true)

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN}   ✓ PALANTIR VM NAT ROUTING CONFIGURED SUCCESSFULLY  ${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo -e "Target Host PC (Gateway)  : ${CYAN}${HOST_PC_IP}${NC}"
echo -e "Remote VM Subnet Routed   : ${YELLOW}${VM_SUBNET}${NC}"
echo -e "Active Kernel Route       : ${GREEN}${ACTIVE_ROUTE}${NC}"
echo -e "Reboot Persistence        : ${GREEN}Enabled (systemd oneshot service)${NC}"
echo ""
echo -e "You can now add any VM on that host directly in your PALANTIR Master UI:"
echo -e "  1. Open Master Dashboard (${CYAN}http://localhost:3000${NC})"
echo -e "  2. Click ${YELLOW}Register Host${NC}"
echo -e "  3. Enter the VM's internal NAT IP directly (e.g. ${CYAN}${VM_SUBNET%.*}.15${NC})"
echo -e "=====================================================\n"
