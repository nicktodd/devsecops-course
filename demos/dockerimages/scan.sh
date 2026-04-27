#!/usr/bin/env bash
# =============================================================================
# scan.sh - Build a Docker image and scan it with Clair v4
#
# Prerequisites:
#   - docker (with access to the Docker socket)
#   - docker compose (v2 plugin)
#   - clairctl  (download: https://github.com/quay/clair/releases)
#               Place the binary on your PATH or in the same directory.
#
# Usage:
#   chmod +x scan.sh
#   ./scan.sh
# =============================================================================
set -euo pipefail

# ---------- Configuration ----------------------------------------------------
IMAGE_NAME="vulnerable-app"
IMAGE_TAG="latest"
LOCAL_REGISTRY="localhost:5000"
FULL_IMAGE="${LOCAL_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
CLAIR_HOST="http://localhost:6060"
COMPOSE_FILE="docker-compose.clair.yml"
REPORT_FILE="clair-report.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- Helper functions -------------------------------------------------
log()  { echo "[*] $*"; }
fail() { echo "[!] $*" >&2; exit 1; }

wait_for_url() {
  local url="$1"
  local label="$2"
  local retries=30
  log "Waiting for ${label} at ${url}..."
  until curl -sf "${url}" > /dev/null 2>&1; do
    retries=$((retries - 1))
    [ "${retries}" -le 0 ] && fail "Timed out waiting for ${label}"
    sleep 5
  done
  log "${label} is ready."
}

# ---------- Check prerequisites ----------------------------------------------
command -v docker        > /dev/null || fail "docker is not installed or not on PATH"
command -v docker        > /dev/null && docker compose version > /dev/null 2>&1 \
  || fail "'docker compose' (v2 plugin) is required"

if ! command -v clairctl > /dev/null 2>&1; then
  log "clairctl not found on PATH - attempting to download..."
  CLAIR_VERSION="v4.7.3"
  curl -fsSL \
    "https://github.com/quay/clair/releases/download/${CLAIR_VERSION}/clairctl-linux-amd64" \
    -o "${SCRIPT_DIR}/clairctl"
  chmod +x "${SCRIPT_DIR}/clairctl"
  export PATH="${SCRIPT_DIR}:${PATH}"
fi

# ---------- Step 1: Build the Docker image -----------------------------------
log "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"

# ---------- Step 2: Tag for the local registry -------------------------------
log "Tagging image for local registry: ${FULL_IMAGE}"
docker tag "${IMAGE_NAME}:${IMAGE_TAG}" "${FULL_IMAGE}"

# ---------- Step 3: Start Clair stack ----------------------------------------
log "Starting Clair stack (Postgres + Clair + local registry) via Docker Compose..."
docker compose -f "${SCRIPT_DIR}/${COMPOSE_FILE}" up -d

# ---------- Step 4: Wait for services to be ready ----------------------------
wait_for_url "http://localhost:5000/v2/"  "Local registry"
wait_for_url "${CLAIR_HOST}/healthz"      "Clair API"

# ---------- Step 5: Push image to local registry -----------------------------
# NOTE: localhost:5000 is treated as an insecure registry by Docker by default.
# If your Docker daemon rejects it, add the following to /etc/docker/daemon.json:
#   { "insecure-registries": ["localhost:5000"] }
log "Pushing image to local registry..."
docker push "${FULL_IMAGE}"

# ---------- Step 6: Run vulnerability scan -----------------------------------
log "Running Clair vulnerability scan against: ${FULL_IMAGE}"
log "Results will be written to: ${REPORT_FILE}"

clairctl --host "${CLAIR_HOST}" report "${FULL_IMAGE}" | tee "${REPORT_FILE}"

log "Scan complete. Full report saved to ${REPORT_FILE}."

# ---------- Step 7: Cleanup --------------------------------------------------
log "Stopping and removing Clair stack containers..."
docker compose -f "${SCRIPT_DIR}/${COMPOSE_FILE}" down

log "Done."
