#!/usr/bin/env bash
# Create the central runtime environment and launch the published image stack.
set -Eeuo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
AGENT_SECRETS_FILE="${REPO_ROOT}/.env.agent-secrets"
LAN_IP="${PALANTIR_LAN_BIND_IP:-}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: ./scripts/setup-central.sh [--lan-ip IPv4]

Creates .env with unique secrets when it does not exist, writes a private
.env.agent-secrets file for remote hosts, then pulls and starts the central
Docker Hub image stack. Existing .env files are preserved.
EOF
}

while (($#)); do
  case "$1" in
    --lan-ip)
      (($# >= 2)) || die "--lan-ip requires an IPv4 address"
      LAN_IP="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

valid_ipv4() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  awk -F. '{
    for (i = 1; i <= 4; i++) if ($i < 0 || $i > 255) exit 1
    if ($1 == 0 || $1 == 127 || $1 >= 224 || ($1 == 169 && $2 == 254)) exit 1
  }' <<<"$candidate"
}

read_env_value() {
  local key="$1" file="$2"
  awk -v key="$key" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$file"
}

valid_secret() {
  local value="$1"
  [[ ${#value} -ge 32 && "$value" =~ ^[A-Za-z0-9._-]+$ ]]
}

command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Engine and the Compose plugin first."
command -v openssl >/dev/null 2>&1 || die "openssl is required to generate runtime secrets."
[[ -f "${REPO_ROOT}/docker-compose.yml" && -f "${REPO_ROOT}/docker-compose.images.yml" ]] || die "Run this script from a PALANTIR checkout."

COMPOSE_VERSION="$(docker compose version --short 2>/dev/null | sed 's/^v//')" || die "Docker Compose v2 is required."
[[ "$COMPOSE_VERSION" =~ ^([0-9]+)\.([0-9]+) ]] || die "Could not determine Docker Compose version."
COMPOSE_MAJOR="${BASH_REMATCH[1]}"
COMPOSE_MINOR="${BASH_REMATCH[2]}"
if (( COMPOSE_MAJOR < 2 || (COMPOSE_MAJOR == 2 && COMPOSE_MINOR < 24) )); then
  die "Docker Compose 2.24 or newer is required; found ${COMPOSE_VERSION}."
fi

cd "$REPO_ROOT"

if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -z "$LAN_IP" ]]; then
    DETECTED_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)"
    if [[ -t 0 ]]; then
      read -r -p "Central server LAN IPv4 address${DETECTED_IP:+ [${DETECTED_IP}]}: " LAN_IP
      LAN_IP="${LAN_IP:-$DETECTED_IP}"
    else
      LAN_IP="$DETECTED_IP"
    fi
  fi
  valid_ipv4 "$LAN_IP" || die "Set the central server's reachable static LAN IP with --lan-ip IPv4."

  info "Generating independent credentials in .env (values will not be printed)"
  TEMP_ENV="$(mktemp "${REPO_ROOT}/.env.tmp.XXXXXX")"
  trap 'rm -f "${TEMP_ENV:-}"' EXIT
  {
    printf 'POSTGRES_USER=palantir\n'
    printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)"
    printf 'POSTGRES_DB=palantir\n'
    printf 'PALANTIR_WEBHOOK_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'PALANTIR_API_READ_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PALANTIR_API_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PALANTIR_API_ENROLL_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PALANTIR_LAN_BIND_IP=%s\n' "$LAN_IP"
    printf 'AUTHENTIK_IMAGE=ghcr.io/goauthentik/server\n'
    printf 'AUTHENTIK_TAG=2026.8.3\n'
    printf 'AUTHENTIK_SECRET_KEY=%s\n' "$(openssl rand -hex 32)"
    printf 'AUTHENTIK_POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)"
    printf 'CORS_ALLOWED_ORIGINS=\n'
    printf 'AGENT_AUTH_TOKEN=%s\n' "$(openssl rand -hex 32)"
    printf 'PALANTIR_BACKEND_IMAGE=abdullahahmadfarooqi/palantir-backend:latest\n'
    printf 'PALANTIR_NETDATA_IMAGE=abdullahahmadfarooqi/palantir-netdata:latest\n'
    printf 'PALANTIR_COLLECTOR_IMAGE=abdullahahmadfarooqi/palantir-host-collector:latest\n'
  } >"$TEMP_ENV"
  chmod 600 "$TEMP_ENV"
  mv "$TEMP_ENV" "$ENV_FILE"
  TEMP_ENV=""
  trap - EXIT
else
  info "Keeping the existing .env; it will not be overwritten"
  [[ -z "$LAN_IP" ]] || [[ "$(read_env_value PALANTIR_LAN_BIND_IP "$ENV_FILE")" == "$LAN_IP" ]] || \
    die "Existing .env has a different PALANTIR_LAN_BIND_IP. Edit .env to the intended server IP and rerun."
fi

chmod 600 "$ENV_FILE" || die "Could not restrict permissions on .env."

for key in POSTGRES_PASSWORD PALANTIR_WEBHOOK_SECRET PALANTIR_API_READ_TOKEN \
  PALANTIR_API_ADMIN_TOKEN PALANTIR_API_ENROLL_TOKEN AUTHENTIK_SECRET_KEY \
  AUTHENTIK_POSTGRES_PASSWORD AGENT_AUTH_TOKEN PALANTIR_LAN_BIND_IP; do
  value="$(read_env_value "$key" "$ENV_FILE")"
  [[ -n "$value" ]] || die ".env is missing a value for ${key}. Set it and rerun."
  case "$key" in
    AUTHENTIK_SECRET_KEY)
      valid_secret "$value" || die ".env value for ${key} must be at least 32 characters and use only letters, digits, dot, underscore, or hyphen."
      ;;
    *TOKEN|*SECRET|*_PASSWORD)
      valid_secret "$value" || die ".env value for ${key} must be at least 32 characters and use only letters, digits, dot, underscore, or hyphen."
      ;;
  esac
done

SECRET_VALUES=(
  "$(read_env_value POSTGRES_PASSWORD "$ENV_FILE")"
  "$(read_env_value PALANTIR_WEBHOOK_SECRET "$ENV_FILE")"
  "$(read_env_value PALANTIR_API_READ_TOKEN "$ENV_FILE")"
  "$(read_env_value PALANTIR_API_ADMIN_TOKEN "$ENV_FILE")"
  "$(read_env_value PALANTIR_API_ENROLL_TOKEN "$ENV_FILE")"
  "$(read_env_value AUTHENTIK_SECRET_KEY "$ENV_FILE")"
  "$(read_env_value AUTHENTIK_POSTGRES_PASSWORD "$ENV_FILE")"
  "$(read_env_value AGENT_AUTH_TOKEN "$ENV_FILE")"
)
for ((i = 0; i < ${#SECRET_VALUES[@]}; i++)); do
  for ((j = i + 1; j < ${#SECRET_VALUES[@]}; j++)); do
    [[ "${SECRET_VALUES[i]}" != "${SECRET_VALUES[j]}" ]] || \
      die "Secret values in .env must be unique; generate a different value for each setting."
  done
done

LAN_IP="$(read_env_value PALANTIR_LAN_BIND_IP "$ENV_FILE")"
valid_ipv4 "$LAN_IP" || die "PALANTIR_LAN_BIND_IP in .env must be a non-loopback IPv4 address reachable from your LAN."

WEBHOOK_SECRET="$(read_env_value PALANTIR_WEBHOOK_SECRET "$ENV_FILE")"
ENROLL_TOKEN="$(read_env_value PALANTIR_API_ENROLL_TOKEN "$ENV_FILE")"
AGENT_TOKEN="$(read_env_value AGENT_AUTH_TOKEN "$ENV_FILE")"
TEMP_AGENT="$(mktemp "${REPO_ROOT}/.env.agent-secrets.tmp.XXXXXX")"
trap 'rm -f "${TEMP_AGENT:-}"' EXIT
{
  printf 'PALANTIR_SERVER_URL=https://palantir.home.arpa\n'
  printf 'PALANTIR_WEBHOOK_SECRET=%s\n' "$WEBHOOK_SECRET"
  printf 'PALANTIR_API_ENROLL_TOKEN=%s\n' "$ENROLL_TOKEN"
  printf 'PALANTIR_AGENT_TOKEN=%s\n' "$AGENT_TOKEN"
  printf 'PALANTIR_NETDATA_IMAGE=abdullahahmadfarooqi/palantir-netdata:latest\n'
  printf 'PALANTIR_COLLECTOR_IMAGE=abdullahahmadfarooqi/palantir-host-collector:latest\n'
} >"$TEMP_AGENT"
chmod 600 "$TEMP_AGENT"
mv "$TEMP_AGENT" "$AGENT_SECRETS_FILE"
TEMP_AGENT=""
trap - EXIT

info "Pulling published images and starting the central platform"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.images.yml)
"${COMPOSE[@]}" pull

# Stop API workers while applying schema changes so an older image cannot race
# the migration during an upgrade. The SQL is also mounted as the fresh-volume
# initialization script, and is idempotent for existing databases.
if [[ -n "$("${COMPOSE[@]}" ps -q backend celery_worker celery_beat)" ]]; then
  "${COMPOSE[@]}" stop backend celery_worker celery_beat
fi
"${COMPOSE[@]}" up -d postgres

POSTGRES_USER="$(read_env_value POSTGRES_USER "$ENV_FILE")"
POSTGRES_DB="$(read_env_value POSTGRES_DB "$ENV_FILE")"
POSTGRES_USER="${POSTGRES_USER:-palantir}"
POSTGRES_DB="${POSTGRES_DB:-palantir}"
database_ready=false
for _ in $(seq 1 60); do
  # On a fresh volume, pg_isready can report the temporary PostgreSQL server
  # used by the image's init scripts. Wait for the seed row written at the end
  # of sql/init.sql so the explicit upgrade migration cannot race first boot.
  if "${COMPOSE[@]}" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -Atqc "SELECT EXISTS (SELECT 1 FROM monitored_nodes WHERE hostname = 'local-node')" 2>/dev/null | grep -qx t; then
    database_ready=true
    break
  fi
  sleep 2
done
[[ "$database_ready" == true ]] || die "PostgreSQL schema initialization did not finish; inspect with: ${COMPOSE[*]} logs postgres"

"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" <"${REPO_ROOT}/sql/init.sql"
"${COMPOSE[@]}" up -d --no-build

cat <<EOF

Central stack is started.
  .env:                 ${ENV_FILE} (mode 600)
  Agent transfer file:  ${AGENT_SECRETS_FILE} (mode 600; contains only remote-agent credentials)
  LAN address:          ${LAN_IP}
  PALANTIR URL:         https://palantir.home.arpa
  Authentik setup:      https://auth.palantir.home.arpa/if/flow/initial-setup/

Add palantir.home.arpa and auth.palantir.home.arpa to LAN DNS, both pointing
to ${LAN_IP}. Restrict central inbound ports 80/443 to your LAN.

After Caddy has started, export its public root certificate:
  docker cp palantir-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt

Copy .env.agent-secrets and caddy-root.crt to each trusted remote host over SSH.
Never copy the central .env or share its read/admin API tokens with a remote host.
EOF
