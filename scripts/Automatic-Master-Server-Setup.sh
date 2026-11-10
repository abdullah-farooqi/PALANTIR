#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PALANTIR Automatic Central Master Server Setup Script (Automatic-Master-Server-Setup.sh)
#
# Fully sets up the PALANTIR Central Master Server:
#  - Generates/validates 32-character secrets in .env
#  - Boots PostgreSQL 16, Redis 7, Celery Workers, FastAPI Backend, & Sensors
#  - Applies PostgreSQL initializations & range-partitioned tables
#  - Installs npm dependencies and launches the Vite React UI on port 3000 (with Admin privileges)
# ─────────────────────────────────────────────────────────────────────────────
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}     PALANTIR Central Master Server Setup Script    ${NC}"
echo -e "${CYAN}=====================================================${NC}"

# 1. Check Requirements (Docker & Node.js/npm)
if ! command -v docker &> /dev/null; then
  echo -e "${RED}ERROR: Docker engine is not installed.${NC}"
  echo -e "Please install Docker: https://docs.docker.com/engine/install/"
  exit 1
fi

if ! command -v npm &> /dev/null; then
  echo -e "${RED}ERROR: Node.js / npm is not installed.${NC}"
  echo -e "Please install Node.js (v18+): https://nodejs.org/"
  exit 1
fi

# 2. Helper function to generate 32-character hex secret
generate_secret() {
  if command -v openssl &> /dev/null; then
    openssl rand -hex 16
  else
    head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
  fi
}

# 3. Setup and Populate .env File
echo -e "${CYAN}[1/4] Preparing environment variables and secrets (.env)...${NC}"

if [ ! -f .env ]; then
  echo -e "${YELLOW}Creating fresh .env from template...${NC}"
  if [ -f .env.example ]; then
    cp .env.example .env
  else
    touch .env
  fi
fi

# Ensure all required secret tokens are present and at least 32 characters
ensure_env_secret() {
  local var_name=$1
  local default_prefix=$2
  
  if ! grep -q "^${var_name}=" .env || [ -z "$(grep "^${var_name}=" .env | cut -d'=' -f2)" ]; then
    local new_sec="${default_prefix}-$(generate_secret)"
    # Ensure min 32 chars
    while [ ${#new_sec} -lt 32 ]; do
      new_sec="${new_sec}-00"
    done
    if grep -q "^${var_name}=" .env; then
      sed -i "s|^${var_name}=.*|${var_name}=${new_sec}|" .env
    else
      echo "${var_name}=${new_sec}" >> .env
    fi
  fi
}

ensure_env_secret "POSTGRES_PASSWORD" "palantir-db"
ensure_env_secret "PALANTIR_WEBHOOK_SECRET" "palantir-webhook"
ensure_env_secret "PALANTIR_API_READ_TOKEN" "palantir-read"
ensure_env_secret "PALANTIR_API_ADMIN_TOKEN" "palantir-admin"
ensure_env_secret "PALANTIR_API_ENROLL_TOKEN" "palantir-enroll"
ensure_env_secret "AUTHENTIK_SECRET_KEY" "palantir-authentik"
ensure_env_secret "AUTHENTIK_POSTGRES_PASSWORD" "palantir-auth-db"
ensure_env_secret "AGENT_AUTH_TOKEN" "palantir-agent"

echo -e "${GREEN}✓ Environment configuration validated.${NC}"

# 4. Check & Handle Occupied Master Server Ports (3000, 8000, 5432, 6379)
echo -e "${CYAN}[2/4] Checking Master Server ports (3000, 8000, 5432, 6379)...${NC}"

port_listener_pids() {
  local port=$1
  local pids=""

  if command -v lsof &> /dev/null; then
    pids=$(lsof -nP -t -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)
  fi
  if [ -z "${pids}" ] && command -v ss &> /dev/null; then
    pids=$(ss -H -ltnp "sport = :${port}" 2>/dev/null \
      | grep -oE 'pid=[0-9]+' \
      | cut -d= -f2 \
      | sort -u || true)
  fi
  printf '%s\n' "${pids}" | sed '/^$/d' | sort -u
}

port_is_listening() {
  local port=$1
  local has_checker=false

  if command -v ss &> /dev/null; then
    has_checker=true
    if ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .; then
      return 0
    fi
  fi
  if command -v lsof &> /dev/null; then
    has_checker=true
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN &> /dev/null; then
      return 0
    fi
  fi
  if [ "${has_checker}" = false ]; then
    echo -e "${RED}ERROR: Neither 'ss' nor 'lsof' is installed; cannot safely check port ${port}.${NC}"
    exit 1
  fi
  return 1
}

port_docker_container_ids() {
  local port=$1
  local ids=""
  ids=$(docker ps -q --filter "publish=${port}" 2>/dev/null || true)
  if [ "${port}" -eq 8000 ]; then
    local backend_id
    backend_id=$(docker ps -q --filter "name=^palantir-backend$" 2>/dev/null || true)
    if [ -n "${backend_id}" ]; then
      ids=$(printf "%s\n%s" "${ids}" "${backend_id}")
    fi
  fi
  printf '%s\n' "${ids}" | sed '/^$/d' | sort -u
}

signal_listener() {
  local signal=$1
  local pid=$2

  if kill -"${signal}" "${pid}" 2>/dev/null; then
    return 0
  fi
  if [ "${EUID}" -ne 0 ] && command -v sudo &> /dev/null; then
    sudo kill -"${signal}" "${pid}"
    return $?
  fi
  return 1
}

check_and_free_port() {
  local port=$1
  local service_name=$2
  local choice container_ids_output pid_output pid
  local -a container_ids=()

  container_ids_output=$(port_docker_container_ids "${port}")
  pid_output=$(port_listener_pids "${port}")
  if [ -z "${container_ids_output}" ] && [ -z "${pid_output}" ] && ! port_is_listening "${port}"; then
    return 0
  fi

  echo -e "${YELLOW}WARNING: Port ${port} (${service_name}) is currently in use!${NC}"
  echo "Choose an option:"
  echo "  [1] Stop the process/container using port ${port} and proceed (Recommended)"
  echo "  [2] Quit setup"
  read -r -p "Select option [1/2] (default 1): " choice || choice="1"
  choice=${choice:-1}

  case "${choice}" in
    1)
      echo -e "${YELLOW}Freeing port ${port}...${NC}"

      if [ -n "${container_ids_output}" ]; then
        mapfile -t container_ids <<< "${container_ids_output}"
        if ! docker stop "${container_ids[@]}"; then
          echo -e "${YELLOW}WARNING: Docker could not stop every container publishing port ${port}.${NC}"
        fi
      fi

      # Also stop any conflicting containers on the system Docker daemon if accessible
      if [ -S /var/run/docker.sock ] && [ "${DOCKER_HOST:-}" != "unix:///var/run/docker.sock" ]; then
        local sys_ids=""
        sys_ids=$(docker -H unix:///var/run/docker.sock ps -q --filter "publish=${port}" 2>/dev/null || true)
        if [ "${port}" -eq 8000 ]; then
          local sys_backend
          sys_backend=$(docker -H unix:///var/run/docker.sock ps -q --filter "name=^palantir-backend$" 2>/dev/null || true)
          [ -n "${sys_backend}" ] && sys_ids=$(printf "%s\n%s" "${sys_ids}" "${sys_backend}")
        elif [ "${port}" -eq 5432 ]; then
          local sys_db
          sys_db=$(docker -H unix:///var/run/docker.sock ps -q --filter "name=^palantir-postgres$" 2>/dev/null || true)
          [ -n "${sys_db}" ] && sys_ids=$(printf "%s\n%s" "${sys_ids}" "${sys_db}")
        elif [ "${port}" -eq 6379 ]; then
          local sys_redis
          sys_redis=$(docker -H unix:///var/run/docker.sock ps -q --filter "name=^palantir-redis$" 2>/dev/null || true)
          [ -n "${sys_redis}" ] && sys_ids=$(printf "%s\n%s" "${sys_ids}" "${sys_redis}")
        fi
        if [ -n "${sys_ids}" ]; then
          docker -H unix:///var/run/docker.sock stop $(echo "${sys_ids}" | tr '\n' ' ') >/dev/null 2>&1 || true
        fi
      fi

      pid_output=$(port_listener_pids "${port}")
      if [ -n "${pid_output}" ]; then
        while IFS= read -r pid; do
          [ -n "${pid}" ] || continue
          if ! signal_listener TERM "${pid}"; then
            echo -e "${YELLOW}Could not send TERM to PID ${pid}; will retry with KILL.${NC}"
          fi
        done <<< "${pid_output}"
        sleep 1

        # Give cooperative services a chance to exit before forcing them down.
        pid_output=$(port_listener_pids "${port}")
        if [ -n "${pid_output}" ]; then
          while IFS= read -r pid; do
            [ -n "${pid}" ] || continue
            if ! signal_listener KILL "${pid}"; then
              echo -e "${RED}ERROR: Could not terminate PID ${pid} on port ${port}.${NC}"
            fi
          done <<< "${pid_output}"
        fi
      fi

      # If process details are hidden from the current user, use fuser with
      # elevated privileges as a last resort, then verify the port below.
      if port_is_listening "${port}" && [ -z "$(port_listener_pids "${port}")" ] && command -v fuser &> /dev/null; then
        if [ "${EUID}" -eq 0 ]; then
          fuser -k -TERM "${port}/tcp" 2>/dev/null || true
        elif command -v sudo &> /dev/null; then
          sudo fuser -k -TERM "${port}/tcp" 2>/dev/null || true
        fi
      fi

      sleep 1
      container_ids_output=$(port_docker_container_ids "${port}")
      if [ -n "${container_ids_output}" ] || port_is_listening "${port}"; then
        echo -e "${RED}ERROR: Port ${port} is still occupied; refusing to start the stack.${NC}"
        if command -v ss &> /dev/null; then
          ss -ltnp "sport = :${port}" 2>/dev/null || true
        elif command -v lsof &> /dev/null; then
          lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true
        fi
        echo "Stop the service shown above, then run this setup script again."
        exit 1
      fi
      echo -e "${GREEN}✓ Port ${port} is free.${NC}"
      ;;
    *)
      echo -e "${RED}Setup aborted by user.${NC}"
      exit 1
      ;;
  esac
}

# Stop existing Palantir stack services before checking ports to avoid self-conflict warnings
docker compose stop backend postgres redis celery_worker celery_beat >/dev/null 2>&1 || true
if [ -S /var/run/docker.sock ] && [ "${DOCKER_HOST:-}" != "unix:///var/run/docker.sock" ]; then
  docker -H unix:///var/run/docker.sock stop palantir-backend palantir-postgres palantir-redis palantir-celery-worker palantir-celery-beat >/dev/null 2>&1 || true
fi

check_and_free_port 3000 "React UI"
check_and_free_port 8000 "FastAPI Backend"
check_and_free_port 5432 "PostgreSQL"
check_and_free_port 6379 "Redis"

# 5. Start Backend Infrastructure Stack with Docker Compose
echo -e "${CYAN}[3/4] Starting PALANTIR Master Backend Stack (PostgreSQL, Redis, Celery, FastAPI)...${NC}"
docker compose up -d --force-recreate backend celery_worker celery_beat postgres redis

echo -e "${CYAN}Waiting for PostgreSQL database healthcheck...${NC}"
until docker exec palantir-postgres pg_isready -U palantir -d palantir &>/dev/null; do
  sleep 2
done

# Synchronize database role password with .env even if volume was initialized previously
POSTGRES_PASS=$(grep "^POSTGRES_PASSWORD=" .env | cut -d'=' -f2)
if [ -n "${POSTGRES_PASS}" ]; then
  docker exec palantir-postgres psql -U palantir -d palantir -c "ALTER USER palantir WITH PASSWORD '${POSTGRES_PASS}';" >/dev/null 2>&1 || true
fi

echo -e "${CYAN}Initializing PostgreSQL schema & partitioned tables...${NC}"
docker exec -i palantir-postgres psql -U palantir -d palantir < sql/init.sql >/dev/null

echo -e "${GREEN}✓ PALANTIR Backend Stack is healthy and running!${NC}"

# 6. Setup and Launch Frontend btop Terminal UI
echo -e "${CYAN}[4/4] Setting up PALANTIR React UI...${NC}"

if [ -d frontend ]; then
  cd frontend
  if [ ! -d node_modules ]; then
    echo -e "${YELLOW}Installing UI npm dependencies...${NC}"
    npm install --quiet
  fi
  
  echo -e "${GREEN}=====================================================${NC}"
  echo -e "${GREEN}   ✓ PALANTIR MASTER SERVER INITIALIZED SUCCESSFULLY  ${NC}"
  echo -e "${GREEN}=====================================================${NC}"
  echo -e "Master Backend API : ${CYAN}http://localhost:8000${NC} (Swagger: ${YELLOW}http://localhost:8000/docs${NC})"
  echo -e "Master UI Dashboard: ${CYAN}http://localhost:3000${NC}"
  echo -e "=====================================================\n"
  echo -e "${CYAN}Starting PALANTIR Terminal UI (Admin Mode)...${NC}\n"

  PALANTIR_UI_ROLE=admin npm run dev -- --strictPort
else
  echo -e "${RED}ERROR: 'frontend' directory not found.${NC}"
  exit 1
fi
