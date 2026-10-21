#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR Universal VM Network & NAT Manager (Automatic-VM-Setup-For-NAT.sh)
#
# Configures connectivity between PALANTIR Master Server and Virtual Machines
# hosted across physical machines and various hypervisors:
#   1. Oracle VirtualBox (NAT Port Forwarding & Bridged Helper)
#   2. KVM / QEMU / libvirt (Kernel Subnet Routing - 192.168.122.0/24)
#   3. VMware Workstation / Player / Fusion (vmnet8 NAT Subnet Route)
#   4. Windows Hyper-V / WSL2 (PowerShell netsh portproxy Helper)
#   5. LXD / Incus / Multipass (Linux Bridge Routing)
#   6. Custom Subnet Route (Any custom CIDR & Host PC Gateway)
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

safe_prompt() {
  local prompt_label="$1"
  local var_target="$2"
  local default_value="${3:-}"
  local val=""

  if [ -n "$default_value" ]; then
    echo -e "${prompt_label} [Default: ${YELLOW}${default_value}${NC}]: "
  else
    echo -e "${prompt_label}: "
  fi

  read -r val || true
  if [ -z "$val" ]; then
    val="$default_value"
  fi
  eval "$var_target=\"\$val\""
}

# VirtualBox keeps its registered VM list in the user's home directory. When
# this script is started with sudo, use the invoking desktop user's registry
# instead of root's empty or unrelated VirtualBox registry.
vboxmanage() {
  if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    sudo -H -u "$SUDO_USER" -- "$VBOXMANAGE_BIN" "$@"
  else
    "$VBOXMANAGE_BIN" "$@"
  fi
}

validate_vbox_vm() {
  local vm_name="$1"

  if [ -z "$vm_name" ]; then
    echo -e "${RED}ERROR: VM name cannot be empty.${NC}"
    exit 1
  fi

  if ! vboxmanage showvminfo "$vm_name" --machinereadable >/dev/null 2>&1; then
    echo -e "${RED}ERROR: VirtualBox cannot find the registered VM '${vm_name}'.${NC}"
    echo -e "Use one of the exact names or UUIDs listed below:${NC}"
    vboxmanage list vms || true
    exit 1
  fi
}

vbox_vm_is_running() {
  vboxmanage showvminfo "$1" --machinereadable 2>/dev/null | grep -Fxq 'VMState="running"'
}

auto_configure_virtualbox() {
  if ! command -v VBoxManage &>/dev/null; then
    echo -e "${RED}ERROR: VBoxManage was not found. Automatic setup requires VirtualBox on this machine.${NC}"
    echo -e "For another hypervisor, run this script with ${CYAN}--manual${NC}."
    return 1
  fi

  VBOXMANAGE_BIN="$(command -v VBoxManage)"
  local vm_name="${PALANTIR_VM_NAME:-PALANTIR-Debian}"
  # The main machine's own collector listens on 20000, so NAT guests use 20001.
  local host_port="${PALANTIR_HOST_PORT:-20001}"
  local guest_port="${PALANTIR_GUEST_PORT:-20000}"

  if ! [[ "$host_port" =~ ^[0-9]{1,5}$ ]] || ! [[ "$guest_port" =~ ^[0-9]{1,5}$ ]] ||
    (( 10#$host_port < 1 || 10#$host_port > 65535 || 10#$guest_port < 1 || 10#$guest_port > 65535 )); then
    echo -e "${RED}ERROR: Host and guest ports must be between 1 and 65535.${NC}"
    return 1
  fi

  local vm_info
  if ! vm_info="$(vboxmanage showvminfo "$vm_name" --machinereadable 2>/dev/null)"; then
    echo -e "${RED}ERROR: VirtualBox could not find '${vm_name}' in the invoking user's VM registry.${NC}"
    echo -e "Registered VirtualBox VMs:"
    vboxmanage list vms || true
    echo -e "Set PALANTIR_VM_NAME to the registered VM name to change the automatic target."
    return 1
  fi

  local nat_index
  nat_index="$(printf '%s\n' "$vm_info" | awk -F= '$1 ~ /^nic[1-8]$/ && $2 == "\"nat\"" {sub(/^nic/, "", $1); print $1; exit}')"
  if [ -z "$nat_index" ]; then
    echo -e "${RED}ERROR: '${vm_name}' has no NAT network adapter; no changes were made.${NC}"
    echo -e "Automatic port forwarding requires a VirtualBox NAT adapter."
    return 1
  fi

  local vm_state
  vm_state="$(printf '%s\n' "$vm_info" | awk -F= '$1 == "VMState" {gsub(/"/, "", $2); print $2; exit}')"

  local host_lan_ip
  host_lan_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="src"){print $(i+1);exit}}')"
  if [ -z "$host_lan_ip" ]; then
    host_lan_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [ -z "$host_lan_ip" ]; then
    echo -e "${RED}ERROR: Could not detect this host's LAN IP; no forwarding rule was changed.${NC}"
    return 1
  fi

  if [ "$vm_state" = "running" ]; then
    vboxmanage controlvm "$vm_name" "natpf${nat_index}" delete palantir 2>/dev/null || true
    if ! vboxmanage controlvm "$vm_name" "natpf${nat_index}" "palantir,tcp,,${host_port},,${guest_port}"; then
      echo -e "${RED}ERROR: Could not apply the live VirtualBox forwarding rule.${NC}"
      return 1
    fi
  elif [ "$vm_state" = "poweroff" ]; then
    vboxmanage modifyvm "$vm_name" "--natpf${nat_index}" delete palantir 2>/dev/null || true
    if ! vboxmanage modifyvm "$vm_name" "--natpf${nat_index}" "palantir,tcp,,${host_port},,${guest_port}"; then
      echo -e "${RED}ERROR: Could not save the VirtualBox forwarding rule.${NC}"
      return 1
    fi
  else
    echo -e "${RED}ERROR: '${vm_name}' is in VirtualBox state '${vm_state:-unknown}'. Start it or fully power it off, then rerun.${NC}"
    return 1
  fi

  echo -e "\n${GREEN}✓ VirtualBox port forwarding configured automatically.${NC}"
  echo -e "VM                        : ${CYAN}${vm_name}${NC}"
  echo -e "Host address              : ${CYAN}${host_lan_ip}:${host_port}${NC}"
  echo -e "Guest port                : ${YELLOW}${guest_port}${NC}"
  echo -e "\nRegister this node in PALANTIR as ${YELLOW}${host_lan_ip}:${host_port}${NC}."
}

apply_kernel_route() {
  local target_subnet="$1"
  local gateway_ip="$2"
  local hypervisor_name="$3"

  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Applying kernel routes requires sudo / root privileges.${NC}"
    echo -e "Please re-run this script with: ${CYAN}sudo bash scripts/Automatic-VM-Setup-For-NAT.sh${NC}"
    exit 1
  fi

  echo -e "\n${CYAN}Verifying network reachability to Host PC (${gateway_ip})...${NC}"
  if ping -c 1 -W 2 "$gateway_ip" &>/dev/null; then
    echo -e "${GREEN}✓ Host PC ${gateway_ip} is reachable on the local network.${NC}"
  else
    echo -e "${YELLOW}WARNING: Ping to ${gateway_ip} did not respond. Proceeding with route...${NC}"
  fi

  echo -e "\n${CYAN}Applying Linux kernel route on Master Server...${NC}"
  ip route replace "$target_subnet" via "$gateway_ip"
  echo -e "${GREEN}✓ Kernel route applied: ${target_subnet} via ${gateway_ip}${NC}"

  # Persist across reboots via systemd
  local service_name="palantir-nat-${hypervisor_name,,}-route.service"
  local service_file="/etc/systemd/system/${service_name}"
  cat <<EOF > "$service_file"
[Unit]
Description=PALANTIR Master Server Route to ${hypervisor_name} VMs
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/ip route replace ${target_subnet} via ${gateway_ip}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  if command -v systemctl &>/dev/null; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$service_name" >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Persistent systemd service enabled (${service_file}).${NC}"
  fi

  echo -e "\n${GREEN}=====================================================${NC}"
  echo -e "${GREEN}   ✓ ${hypervisor_name} VM NAT ROUTE CONFIGURED SUCCESSFULLY  ${NC}"
  echo -e "${GREEN}=====================================================${NC}"
  echo -e "Host PC Gateway           : ${CYAN}${gateway_ip}${NC}"
  echo -e "Remote VM Subnet Routed   : ${YELLOW}${target_subnet}${NC}"
  echo -e "Reboot Persistence        : ${GREEN}Enabled (${service_name})${NC}"
  echo -e "\nIn your PALANTIR Master UI (${CYAN}http://localhost:3000${NC}):"
  echo -e "  • Click ${YELLOW}+ Add Node${NC}"
  echo -e "  • Host IP: Enter the VM's internal IP directly (e.g. ${CYAN}${target_subnet%.*}.15${NC})"
  echo -e "=====================================================\n"
}

case "${1:-}" in
  ""|--auto)
    auto_configure_virtualbox
    exit 0
    ;;
  --manual)
    ;;
  *)
    echo -e "Usage: $0 [--auto|--manual]"
    exit 2
    ;;
esac

echo -e "${CYAN}${BOLD}=====================================================${NC}"
echo -e "${CYAN}${BOLD}   PALANTIR Universal VM & NAT Network Manager       ${NC}"
echo -e "${CYAN}${BOLD}=====================================================${NC}"

echo -e "\n${BOLD}Select your VM hypervisor or virtualization environment:${NC}"
echo -e "  ${CYAN}[1] Oracle VirtualBox (NAT Port Forwarding & Bridged Helper)${NC}"
echo -e "  ${CYAN}[2] KVM / QEMU / libvirt (Subnet static route - default 192.168.122.0/24)${NC}"
echo -e "  ${CYAN}[3] VMware Workstation / Player (Subnet static route - vmnet8 NAT)${NC}"
echo -e "  ${CYAN}[4] Windows Hyper-V / WSL2 (PowerShell portproxy Helper)${NC}"
echo -e "  ${CYAN}[5] LXD / Incus / Multipass (Linux Container & VM Bridge Route)${NC}"
echo -e "  ${CYAN}[6] Custom Subnet Route (Enter any custom gateway IP & CIDR)${NC}"

safe_prompt "Select option [1-6]" CHOICE "1"

# =============================================================================
# OPTION 1: ORACLE VIRTUALBOX
# =============================================================================
if [ "$CHOICE" = "1" ]; then
  echo -e "\n${CYAN}--- Oracle VirtualBox NAT Manager ---${NC}"
  echo -e "  ${CYAN}[1] Configure Port Forwarding (Recommended for VirtualBox NAT)${NC}"
  echo -e "  ${CYAN}[2] Convert VM to Bridged Adapter (Gives VM its own real LAN IP)${NC}"
  safe_prompt "Select VirtualBox mode [1/2]" VBOX_MODE "1"

  if [ "$VBOX_MODE" = "1" ]; then
    if command -v VBoxManage &>/dev/null; then
      VBOXMANAGE_BIN="$(command -v VBoxManage)"
      echo -e "${GREEN}✓ Detected Oracle VirtualBox (VBoxManage) on this machine.${NC}"
      echo -e "\n${BOLD}Available Virtual Machines:${NC}"
      vboxmanage list vms || true
      echo ""

      safe_prompt "Enter exact VM Name (or UUID)" VM_NAME ""
      validate_vbox_vm "$VM_NAME"

      safe_prompt "Enter Host Port to expose on this PC" HOST_PORT "20001"
      safe_prompt "Enter Guest Agent Port inside VM" GUEST_PORT "20000"

      vboxmanage controlvm "$VM_NAME" natpf1 delete palantir 2>/dev/null || true
      vboxmanage modifyvm "$VM_NAME" --natpf1 delete palantir 2>/dev/null || true

      if vbox_vm_is_running "$VM_NAME"; then
        echo -e "\n[INFO] VM '$VM_NAME' is running. Applying live rule..."
        vboxmanage controlvm "$VM_NAME" natpf1 "palantir,tcp,,${HOST_PORT},,${GUEST_PORT}"
      else
        echo -e "\n[INFO] VM '$VM_NAME' is powered off. Updating VM configuration..."
        vboxmanage modifyvm "$VM_NAME" --natpf1 "palantir,tcp,,${HOST_PORT},,${GUEST_PORT}"
      fi

      HOST_LAN_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="src"){print $(i+1);exit}}')
      if [ -z "$HOST_LAN_IP" ]; then
        HOST_LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
      fi
      echo -e "\n${GREEN}=====================================================${NC}"
      echo -e "${GREEN}   ✓ VIRTUALBOX PORT FORWARDING CONFIGURED           ${NC}"
      echo -e "${GREEN}=====================================================${NC}"
      echo -e "Host System IP            : ${CYAN}${HOST_LAN_IP}${NC}"
      echo -e "Forwarded Port            : ${YELLOW}${HOST_PORT}${NC} -> VM:${GUEST_PORT}"
      echo -e "\nIn your PALANTIR Master Server Web UI (${CYAN}http://localhost:3000${NC}):"
      echo -e "  • Click ${YELLOW}+ Add Node${NC}"
      echo -e "  • Host IP: ${YELLOW}${HOST_LAN_IP}:${HOST_PORT}${NC}"
      echo -e "=====================================================\n"
      exit 0
    else
      echo -e "${YELLOW}VBoxManage not detected locally. Assuming script is running on Master Server.${NC}"
      safe_prompt "Enter LAN IP of the PC hosting VirtualBox (e.g. PC2)" HOST_PC_IP ""
      safe_prompt "Enter the forwarded port for this VM" TARGET_PORT "20001"

      if [ -z "$HOST_PC_IP" ]; then
        echo -e "${RED}ERROR: Host PC IP cannot be empty.${NC}"
        exit 1
      fi

      echo -e "\nVerifying connection to http://${HOST_PC_IP}:${TARGET_PORT}..."
      if curl -s --connect-timeout 3 "http://${HOST_PC_IP}:${TARGET_PORT}/api/v1/diagnostics" &>/dev/null; then
        echo -e "${GREEN}✓ Connection SUCCESSFUL! VirtualBox agent is responding.${NC}"
        echo -e "\nRegister in PALANTIR UI as: ${YELLOW}${HOST_PC_IP}:${TARGET_PORT}${NC}"
      else
        echo -e "${YELLOW}! Port ${TARGET_PORT} on ${HOST_PC_IP} is not answering yet.${NC}"
        echo -e "\nRun this command on the PC hosting VirtualBox (PC2):"
        echo -e "  ${CYAN}VBoxManage controlvm \"<VM_NAME>\" natpf1 \"palantir,tcp,,${TARGET_PORT},,20000\"${NC}"
      fi
      exit 0
    fi
  else
    if ! command -v VBoxManage &>/dev/null; then
      echo -e "${RED}ERROR: VBoxManage not found. Run this on the machine hosting VirtualBox.${NC}"
      exit 1
    fi
    VBOXMANAGE_BIN="$(command -v VBoxManage)"
    vboxmanage list vms || true
    safe_prompt "Enter exact VM Name" VM_NAME ""
    validate_vbox_vm "$VM_NAME"
    DEFAULT_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    safe_prompt "Enter Host Network Interface to bridge" BRIDGE_IFACE "$DEFAULT_IFACE"
    vboxmanage modifyvm "$VM_NAME" --nic1 bridged --bridgeadapter1 "$BRIDGE_IFACE"
    echo -e "${GREEN}✓ VM '$VM_NAME' switched to Bridged mode on ${BRIDGE_IFACE}.${NC}"
    exit 0
  fi
fi

# =============================================================================
# OPTION 2: KVM / QEMU / LIBVIRT
# =============================================================================
if [ "$CHOICE" = "2" ]; then
  echo -e "\n${CYAN}--- KVM / QEMU / libvirt Master Server Static Route ---${NC}"
  safe_prompt "Enter LAN IP of the physical PC hosting KVM (e.g. PC2)" HOST_PC_IP ""
  safe_prompt "Enter KVM VM Subnet" KVM_SUBNET "192.168.122.0/24"
  apply_kernel_route "$KVM_SUBNET" "$HOST_PC_IP" "KVM"
  exit 0
fi

# =============================================================================
# OPTION 3: VMWARE WORKSTATION / PLAYER
# =============================================================================
if [ "$CHOICE" = "3" ]; then
  echo -e "\n${CYAN}--- VMware Workstation / Player NAT Route ---${NC}"
  safe_prompt "Enter LAN IP of the physical PC hosting VMware (e.g. PC2)" HOST_PC_IP ""
  safe_prompt "Enter VMware NAT Subnet (typically vmnet8, e.g. 192.168.200.0/24)" VMWARE_SUBNET "192.168.200.0/24"
  apply_kernel_route "$VMWARE_SUBNET" "$HOST_PC_IP" "VMware"
  exit 0
fi

# =============================================================================
# OPTION 4: WINDOWS HYPER-V / WSL2
# =============================================================================
if [ "$CHOICE" = "4" ]; then
  echo -e "\n${CYAN}--- Windows Hyper-V / WSL2 Port Forwarding ---${NC}"
  safe_prompt "Enter Windows Host LAN IP" WIN_HOST_IP "192.168.1.50"
  safe_prompt "Enter Hyper-V / WSL2 internal IP (e.g. 172.x.x.x)" VM_INTERNAL_IP "172.28.10.15"
  safe_prompt "Enter Port to expose on Windows Host" WIN_PORT "20000"

  echo -e "\n${BOLD}To expose this VM through Windows Host, run this in PowerShell (Run as Administrator) on Windows:${NC}"
  echo -e "${CYAN}netsh interface portproxy add v4tov4 listenport=${WIN_PORT} listenaddress=0.0.0.0 connectport=20000 connectaddress=${VM_INTERNAL_IP}${NC}"
  echo -e "\nTo allow through Windows Firewall, run in PowerShell:"
  echo -e "${CYAN}New-NetFirewallRule -DisplayName \"PALANTIR Agent Port ${WIN_PORT}\" -Direction Inbound -LocalPort ${WIN_PORT} -Protocol TCP -Action Allow${NC}"
  echo -e "\nIn your PALANTIR Master UI (${CYAN}http://localhost:3000${NC}):"
  echo -e "  • Click ${YELLOW}+ Add Node${NC}"
  echo -e "  • Host IP: ${YELLOW}${WIN_HOST_IP}:${WIN_PORT}${NC}"
  exit 0
fi

# =============================================================================
# OPTION 5: LXD / INCUS / MULTIPASS
# =============================================================================
if [ "$CHOICE" = "5" ]; then
  echo -e "\n${CYAN}--- LXD / Incus / Multipass Linux Bridge Routing ---${NC}"
  safe_prompt "Enter LAN IP of Host PC running LXD/Multipass" HOST_PC_IP ""
  safe_prompt "Enter Bridge Subnet (e.g. 10.0.4.0/24 for lxdbr0 / mpbr0)" BRIDGE_SUBNET "10.0.4.0/24"
  apply_kernel_route "$BRIDGE_SUBNET" "$HOST_PC_IP" "LXD-Multipass"
  exit 0
fi

# =============================================================================
# OPTION 6: CUSTOM SUBNET ROUTE
# =============================================================================
if [ "$CHOICE" = "6" ]; then
  echo -e "\n${CYAN}--- Custom Subnet Static Route ---${NC}"
  safe_prompt "Enter Gateway Host PC LAN IP" HOST_PC_IP ""
  safe_prompt "Enter Target Subnet CIDR (e.g. 10.10.0.0/16)" CUSTOM_SUBNET ""
  if [ -z "$CUSTOM_SUBNET" ]; then
    echo -e "${RED}ERROR: Subnet CIDR cannot be empty.${NC}"
    exit 1
  fi
  apply_kernel_route "$CUSTOM_SUBNET" "$HOST_PC_IP" "Custom"
  exit 0
fi

echo -e "${RED}Invalid choice. Exiting.${NC}"
exit 1
