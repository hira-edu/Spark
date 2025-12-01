#!/usr/bin/env bash

set -euo pipefail

# Build the web UI, embed it, build the server with CGO enabled by default,
# then restart the running services (server + Caddy cache flush/reload).

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export GO111MODULE=on
export CGO_ENABLED="${CGO_ENABLED:-1}"
export COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"

ROCKET_SERVICE_NAME="${ROCKET_SERVICE_NAME:-rocket-server}"
CADDY_SERVICE_NAME="${CADDY_SERVICE_NAME:-caddy}"
STATIK_BIN="${STATIK_BIN:-$(go env GOPATH | cut -d':' -f1)/bin/statik}"
HOST_OS="$(go env GOOS)"
HOST_ARCH="$(go env GOARCH)"

info() { printf '[build] %s\n' "$*"; }
warn() { printf '[warn] %s\n' "$*" >&2; }

ensure_statik() {
  if command -v statik >/dev/null 2>&1; then
    STATIK_BIN="$(command -v statik)"
    return
  fi
  if [ -x "$STATIK_BIN" ]; then
    return
  fi
  info "statik not found, installing..."
  go install github.com/rakyll/statik@latest
}

build_web() {
  info "installing web deps (npm ci)"
  npm ci --prefix "$ROOT_DIR/web"
  info "building web bundle"
  npm run build-prod --prefix "$ROOT_DIR/web"
}

embed_web() {
  ensure_statik
  info "embedding web/dist into server binary (statik)"
  "$STATIK_BIN" -m -src="$ROOT_DIR/web/dist" -f -dest="$ROOT_DIR/server/embed" -p web -ns web
}

build_server() {
  info "building server for ${HOST_OS}/${HOST_ARCH} with CGO_ENABLED=${CGO_ENABLED}"
  go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o "$ROOT_DIR/releases/server_${HOST_OS}_${HOST_ARCH}" "$ROOT_DIR/server"
}

restart_service() {
  local name="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "$name" && return 0
  fi
  if command -v service >/dev/null 2>&1; then
    service "$name" restart && return 0
  fi
  return 1
}

reload_caddy_cli() {
  if command -v caddy >/dev/null 2>&1; then
    caddy reload --force >/dev/null 2>&1 && return 0
    caddy restart >/dev/null 2>&1 && return 0
  fi
  return 1
}

flush_caddy_cache() {
  local dirs=(
    "/var/cache/caddy"
    "/var/lib/caddy/.cache"
    "$HOME/.local/share/caddy"
  )
  for d in "${dirs[@]}"; do
    if [ -d "$d" ]; then
      info "clearing Caddy cache at $d"
      rm -rf "${d:?}/"* || warn "failed to clear $d (permission issue?)"
    fi
  done
}

restart_stack() {
  info "restarting ${ROCKET_SERVICE_NAME} (if present)"
  restart_service "$ROCKET_SERVICE_NAME" || warn "could not restart ${ROCKET_SERVICE_NAME} (service not found?)"

  flush_caddy_cache
  if restart_service "$CADDY_SERVICE_NAME"; then
    info "restarted ${CADDY_SERVICE_NAME} via service manager"
    return
  fi
  if reload_caddy_cli; then
    info "reloaded caddy via CLI"
    return
  fi
  warn "Caddy not restarted (service/CLI missing)"
}

build_web
embed_web
build_server
restart_stack

info "done"
