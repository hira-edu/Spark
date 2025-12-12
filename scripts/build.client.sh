#!/usr/bin/env bash

set -euo pipefail

export GO111MODULE=auto
export COMMIT="$(git rev-parse HEAD)"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/built"
mkdir -p "${OUT_DIR}"

# Default to CGO enabled on the host, but disable it for cross builds unless
# explicitly overridden (cross sysroot libs are not always available).
CGO_ENABLED_NATIVE="${CGO_ENABLED_NATIVE:-1}"
CGO_ENABLED_CROSS="${CGO_ENABLED_CROSS:-0}"

build_linux() {
  export GOOS=linux

  export GOARCH=arm
  export CGO_ENABLED="${CGO_ENABLED_CROSS}"
  unset CC CXX
  if [ "${CGO_ENABLED}" = "1" ]; then
    export CC=arm-linux-gnueabihf-gcc
    export CXX=arm-linux-gnueabihf-g++
  fi
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/linux_arm" Rocket/client

  # Linux i386 requires multilib which conflicts with cross-compilers
  # Building without CGO
  export GOARCH=386
  export CGO_ENABLED=0
  unset CC CXX
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/linux_i386" Rocket/client

  export GOARCH=arm64
  export CGO_ENABLED="${CGO_ENABLED_CROSS}"
  unset CC CXX
  if [ "${CGO_ENABLED}" = "1" ]; then
    export CC=aarch64-linux-gnu-gcc
    export CXX=aarch64-linux-gnu-g++
  fi
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/linux_arm64" Rocket/client

  export GOARCH=amd64
  export CGO_ENABLED="${CGO_ENABLED_NATIVE}"
  unset CC CXX
  if [ "${CGO_ENABLED}" = "1" ]; then
    export CC=gcc
    export CXX=g++
  fi
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/linux_amd64" Rocket/client
}

build_windows() {
  export GOOS=windows

  export GOARCH=386
  export CGO_ENABLED="${CGO_ENABLED_CROSS}"
  unset CC CXX
  if [ "${CGO_ENABLED}" = "1" ]; then
    export CC=i686-w64-mingw32-gcc
    export CXX=i686-w64-mingw32-g++
  fi
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/windows_i386.exe" Rocket/client

  export GOARCH=amd64
  export CGO_ENABLED="${CGO_ENABLED_CROSS}"
  unset CC CXX
  if [ "${CGO_ENABLED}" = "1" ]; then
    export CC=x86_64-w64-mingw32-gcc
    export CXX=x86_64-w64-mingw32-g++
  fi
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/windows_amd64.exe" Rocket/client

  # Windows ARM64 requires special cross-compiler (not available in standard Ubuntu repos)
  # Building without CGO for now
  export GOARCH=arm64
  export CGO_ENABLED=0
  unset CC CXX
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" -o "${OUT_DIR}/windows_arm64.exe" Rocket/client

  # Server looks for binaries without .exe extension.
  cp -f "${OUT_DIR}/windows_i386.exe" "${OUT_DIR}/windows_i386"
  cp -f "${OUT_DIR}/windows_amd64.exe" "${OUT_DIR}/windows_amd64"
  cp -f "${OUT_DIR}/windows_arm64.exe" "${OUT_DIR}/windows_arm64"
}

build_linux
build_windows
