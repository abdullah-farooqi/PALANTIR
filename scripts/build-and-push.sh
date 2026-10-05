#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# PALANTIR Automated Build & Push Script (Docker Hub & GHCR)
#
# Usage:
#   ./scripts/build-and-push.sh --hub <dockerhub-username> --tag 1.0.0
#   ./scripts/build-and-push.sh --ghcr <github-username> --tag 1.0.0
#   ./scripts/build-and-push.sh --hub <user> --ghcr <user> --tag 1.0.0
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

HUB_USER=""
GHCR_USER=""
TAG="latest"
BUILD_ONLY=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --hub)
      HUB_USER="$2"
      shift 2
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
      echo "Usage: $0 [--hub <DOCKERHUB_USER>] [--ghcr <GITHUB_USER>] [--tag <VERSION>] [--build-only]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "$HUB_USER" ] && [ -z "$GHCR_USER" ] && [ "$BUILD_ONLY" = false ]; then
  echo "Error: Specify at least one registry: --hub <username> or --ghcr <username> (or use --build-only)"
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================================="
echo "PALANTIR Container Build & Release Pipeline"
echo "  Project Root: $PROJECT_ROOT"
echo "  Target Tag:   $TAG"
[ -n "$HUB_USER" ] && echo "  Docker Hub:   $HUB_USER"
[ -n "$GHCR_USER" ] && echo "  GHCR:         ghcr.io/$GHCR_USER"
echo "=========================================================="

# 1. Build Backend Image
echo ""
echo ">>> Building palantir-backend..."
docker build -t palantir-backend:"$TAG" -t palantir-backend:latest ./backend

# 2. Build Netdata Sensor Image
echo ""
echo ">>> Building palantir-netdata..."
docker build -t palantir-netdata:"$TAG" -t palantir-netdata:latest ./services/netdata

echo ""
echo ">>> Building palantir-host-collector..."
docker build -t palantir-host-collector:"$TAG" -t palantir-host-collector:latest ./agent

echo ""
echo "✓ Local build complete for palantir-backend, palantir-netdata and palantir-host-collector."

if [ "$BUILD_ONLY" = true ]; then
  echo "Build-only flag specified. Skipping registry pushes."
  exit 0
fi

# 3. Tag and Push to Docker Hub
if [ -n "$HUB_USER" ]; then
  echo ""
  echo ">>> Tagging and pushing to Docker Hub ($HUB_USER)..."
  docker tag palantir-backend:"$TAG" "$HUB_USER"/palantir-backend:"$TAG"
  docker tag palantir-backend:latest "$HUB_USER"/palantir-backend:latest
  docker tag palantir-netdata:"$TAG" "$HUB_USER"/palantir-netdata:"$TAG"
  docker tag palantir-netdata:latest "$HUB_USER"/palantir-netdata:latest
  docker tag palantir-host-collector:"$TAG" "$HUB_USER"/palantir-host-collector:"$TAG"
  docker tag palantir-host-collector:latest "$HUB_USER"/palantir-host-collector:latest

  echo "Pushing $HUB_USER/palantir-backend:$TAG..."
  docker push "$HUB_USER"/palantir-backend:"$TAG"
  docker push "$HUB_USER"/palantir-backend:latest

  echo "Pushing $HUB_USER/palantir-netdata:$TAG..."
  docker push "$HUB_USER"/palantir-netdata:"$TAG"
  docker push "$HUB_USER"/palantir-netdata:latest
  echo "Pushing $HUB_USER/palantir-host-collector:$TAG..."
  docker push "$HUB_USER"/palantir-host-collector:"$TAG"
  docker push "$HUB_USER"/palantir-host-collector:latest
  echo "✓ Docker Hub push complete."
fi

# 4. Tag and Push to GitHub Container Registry (GHCR)
if [ -n "$GHCR_USER" ]; then
  echo ""
  echo ">>> Tagging and pushing to GitHub Container Registry (ghcr.io/$GHCR_USER)..."
  GHCR_PREFIX="ghcr.io/${GHCR_USER,,}"

  docker tag palantir-backend:"$TAG" "$GHCR_PREFIX"/palantir-backend:"$TAG"
  docker tag palantir-backend:latest "$GHCR_PREFIX"/palantir-backend:latest
  docker tag palantir-netdata:"$TAG" "$GHCR_PREFIX"/palantir-netdata:"$TAG"
  docker tag palantir-netdata:latest "$GHCR_PREFIX"/palantir-netdata:latest
  docker tag palantir-host-collector:"$TAG" "$GHCR_PREFIX"/palantir-host-collector:"$TAG"
  docker tag palantir-host-collector:latest "$GHCR_PREFIX"/palantir-host-collector:latest

  echo "Pushing $GHCR_PREFIX/palantir-backend:$TAG..."
  docker push "$GHCR_PREFIX"/palantir-backend:"$TAG"
  docker push "$GHCR_PREFIX"/palantir-backend:latest

  echo "Pushing $GHCR_PREFIX/palantir-netdata:$TAG..."
  docker push "$GHCR_PREFIX"/palantir-netdata:"$TAG"
  docker push "$GHCR_PREFIX"/palantir-netdata:latest
  echo "Pushing $GHCR_PREFIX/palantir-host-collector:$TAG..."
  docker push "$GHCR_PREFIX"/palantir-host-collector:"$TAG"
  docker push "$GHCR_PREFIX"/palantir-host-collector:latest
  echo "✓ GHCR push complete."
fi

echo ""
echo "=========================================================="
echo "✓ All images successfully built, tagged, and pushed!"
echo "=========================================================="
