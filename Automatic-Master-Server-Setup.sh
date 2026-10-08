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
cd "$SCRIPT_DIR"

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

check_and_free_port() {
  local port=$1
  local service_name=$2
  if lsof -i :$port &> /dev/null || netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
    echo -e "${YELLOW}WARNING: Port $port ($service_name) is currently in use!${NC}"
    echo -e "Choose an option:"
    echo "  [1] Automatically terminate process on port $port and proceed (Recommended)"
    echo "  [2] Quit setup"
    read -r -p "Select option [1/2]: " choice < /dev/tty || choice="1"
    case "$choice" in
      1)
        echo -e "${YELLOW}Terminating process occupying port $port...${NC}"
        fuser -k -9 ${port}/tcp 2>/dev/null || true
        pids=$(ss -tulpn "sport = :${port}" 2>/dev/null | grep -oP 'pid=\K\d+' | sort -u || true)
        if [ -n "$pids" ]; then
          echo "$pids" | xargs -r kill -9 2>/dev/null || true
        fi
        docker ps -q --filter "publish=${port}" | xargs -r docker stop 2>/dev/null || true
        sleep 1
        ;;
      *)
        echo -e "${RED}Setup aborted by user.${NC}"
        exit 1
        ;;
    esac
  fi
}

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

  PALANTIR_UI_ROLE=admin npm run dev
else
  echo -e "${RED}ERROR: 'frontend' directory not found.${NC}"
  exit 1
fi
