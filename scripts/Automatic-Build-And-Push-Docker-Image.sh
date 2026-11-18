#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# PALANTIR Automated Build & Push Script (Docker Hub & GHCR)
#
# Builds the backend + host-collector images from this checkout and
# publishes them so other hosts can pull without compiling.
#
# Usage:
#   ./scripts/Automatic-Build-And-Push-Docker-Image.sh
#   ./scripts/Automatic-Build-And-Push-Docker-Image.sh --hub abdullahahmadfarooqi --tag 1.0.0
#   ./scripts/Automatic-Build-And-Push-Docker-Image.sh --build-only
#   ./scripts/Automatic-Build-And-Push-Docker-Image.sh --hub <user> --ghcr <user> --tag 1.0.0
#
# Defaults:
#   --hub abdullahahmadfarooqi
#   --tag latest  (also tags the short git SHA when available)
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

HUB_USER="${PALANTIR_DOCKERHUB_USER:-abdullahahmadfarooqi}"
GHCR_USER=""
TAG="latest"
BUILD_ONLY=false
PUSH_HUB=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --hub)
      HUB_USER="$2"
      PUSH_HUB=true
      shift 2
      ;;
    --no-hub)
      PUSH_HUB=false
      HUB_USER=""
      shift
      ;;
    --ghcr)
      GHCR_USER="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --build-only)
      BUILD_ONLY=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--hub <DOCKERHUB_USER>] [--no-hub] [--ghcr <GITHUB_USER>] [--tag <VERSION>] [--build-only]"
      echo
      echo "Default Docker Hub user: abdullahahmadfarooqi"
      echo "Images: palantir-backend, palantir-host-collector"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ "$BUILD_ONLY" = false ] && [ "$PUSH_HUB" = false ] && [ -z "$GHCR_USER" ]; then
  echo "Error: Specify a registry (--hub / --ghcr) or use --build-only"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || true)"
BUILD_DATE="$(date -u +%Y%m%d)"

echo "=========================================================="
echo "PALANTIR Container Build & Release Pipeline"
echo "  Project Root: $PROJECT_ROOT"
echo "  Target Tag:   $TAG"
[ -n "$GIT_SHA" ] && echo "  Git SHA:      $GIT_SHA"
[ "$PUSH_HUB" = true ] && [ -n "$HUB_USER" ] && echo "  Docker Hub:   $HUB_USER"
[ -n "$GHCR_USER" ] && echo "  GHCR:         ghcr.io/$GHCR_USER"
echo "=========================================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not on PATH."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Error: cannot talk to the Docker daemon. Start Docker and retry."
  exit 1
fi

if [ "$BUILD_ONLY" = false ] && [ "$PUSH_HUB" = true ] && [ -n "$HUB_USER" ]; then
  echo ">>> Using Docker Hub namespace: ${HUB_USER}"
  echo "    If push fails with unauthorized, run: docker login"
fi

# 1. Build Backend Image
echo ""
echo ">>> Building palantir-backend..."
docker build \
  -t palantir-backend:"$TAG" \
  -t palantir-backend:latest \
  ${GIT_SHA:+-t palantir-backend:"$GIT_SHA"} \
  ${GIT_SHA:+-t palantir-backend:"$BUILD_DATE-$GIT_SHA"} \
  ./backend

# 2. Build Palantir Host Collector Image
echo ""
echo ">>> Building palantir-host-collector..."
docker build \
  -t palantir-host-collector:"$TAG" \
  -t palantir-host-collector:latest \
  ${GIT_SHA:+-t palantir-host-collector:"$GIT_SHA"} \
  ${GIT_SHA:+-t palantir-host-collector:"$BUILD_DATE-$GIT_SHA"} \
  ./agent

echo ""
echo "✓ Local build complete for palantir-backend and palantir-host-collector."

if [ "$BUILD_ONLY" = true ]; then
  echo "Build-only flag specified. Skipping registry pushes."
  exit 0
fi

push_image_set() {
  local prefix="$1"
  local name="$2"
  local -a versions=()
  local version

  add_version() {
    local candidate="$1"
    local existing
    for existing in "${versions[@]+"${versions[@]}"}"; do
      [ "$existing" = "$candidate" ] && return 0
    done
    versions+=("$candidate")
  }

  add_version "$TAG"
  add_version "latest"
  [ -n "$GIT_SHA" ] && add_version "$GIT_SHA" && add_version "$BUILD_DATE-$GIT_SHA"

  for version in "${versions[@]}"; do
    docker tag "palantir-${name}:${version}" "${prefix}/palantir-${name}:${version}"
    echo "Pushing ${prefix}/palantir-${name}:${version}..."
    docker push "${prefix}/palantir-${name}:${version}"
  done
}

# 3. Tag and Push to Docker Hub
if [ "$PUSH_HUB" = true ] && [ -n "$HUB_USER" ]; then
  echo ""
  echo ">>> Tagging and pushing to Docker Hub ($HUB_USER)..."
  push_image_set "$HUB_USER" "backend"
  push_image_set "$HUB_USER" "host-collector"
  echo "✓ Docker Hub push complete."
fi

# 4. Tag and Push to GitHub Container Registry (GHCR)
if [ -n "$GHCR_USER" ]; then
  echo ""
  echo ">>> Tagging and pushing to GitHub Container Registry (ghcr.io/$GHCR_USER)..."
  GHCR_PREFIX="ghcr.io/${GHCR_USER,,}"
  push_image_set "$GHCR_PREFIX" "backend"
  push_image_set "$GHCR_PREFIX" "host-collector"
  echo "✓ GHCR push complete."
fi

echo ""
echo "=========================================================="
echo "✓ Images built and published."
echo ""
echo "On the master server (after git pull):"
echo "  sudo bash scripts/Automatic-Master-Server-Setup.sh"
echo ""
echo "On each telemetry host (no repo clone required):"
if [ -n "$HUB_USER" ]; then
  echo "  curl -fsSL https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetery_immproved_ui/scripts/Automatic-Host-Setup.sh | sudo env COLLECTOR_IMAGE=${HUB_USER}/palantir-host-collector:latest bash"
  echo ""
  echo "  # or with the master's AGENT_AUTH_TOKEN already set:"
  echo "  sudo PALANTIR_AGENT_TOKEN=<token> COLLECTOR_IMAGE=${HUB_USER}/palantir-host-collector:latest bash Automatic-Host-Setup.sh"
else
  echo "  sudo bash scripts/Automatic-Host-Setup.sh"
fi
echo "=========================================================="
