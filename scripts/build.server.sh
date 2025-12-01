#!/usr/bin/env bash

set -euo pipefail

export GO111MODULE=auto
export COMMIT=`git rev-parse HEAD`
# Default to CGO enabled (can be overridden via env)
export CGO_ENABLED=${CGO_ENABLED:-1}

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
release_dir="${root_dir}/releases"
mkdir -p "${release_dir}"

build_target() {
  local os="$1"
  local arch="$2"
  local out="$3"
  local cgo="${4:-$CGO_ENABLED}"

  GOOS="$os" GOARCH="$arch" CGO_ENABLED="$cgo" \
    go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o "${release_dir}/${out}" Rocket/server
}


export GOOS=darwin

build_target darwin arm64 server_darwin_arm64
build_target darwin amd64 server_darwin_amd64



export GOOS=linux

build_target linux arm server_linux_arm "${CGO_ENABLED_CROSS:-0}"
build_target linux 386 server_linux_i386 "${CGO_ENABLED_CROSS:-0}"
build_target linux arm64 server_linux_arm64 "${CGO_ENABLED_CROSS:-0}"
build_target linux amd64 server_linux_amd64 "${CGO_ENABLED}"



export GOOS=windows

build_target windows 386 server_windows_i386.exe "${CGO_ENABLED_CROSS:-0}"
build_target windows arm64 server_windows_arm64.exe "${CGO_ENABLED_CROSS:-0}"
build_target windows amd64 server_windows_amd64.exe "${CGO_ENABLED_CROSS:-0}"
