#!/usr/bin/env bash
# Builds the Go tool (Windows amd64 + arm64, Linux amd64) and the fake
# tailscale used by tests. Needs Go on PATH (or GO=/path/to/go).
set -eu
cd "$(dirname "$0")/go"
GO=${GO:-go}
export CGO_ENABLED=0

GOOS=windows GOARCH=amd64 "$GO" build -trimpath -ldflags="-s -w" -o ../tailscale-audit.exe .
GOOS=windows GOARCH=arm64 "$GO" build -trimpath -ldflags="-s -w" -o ../tailscale-audit-arm64.exe .
GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags="-s -w" -o ../tailscale-audit-linux-amd64 .

# test helper for this machine
"$GO" build -o ../tests/fakets/tailscale"$("$GO" env GOEXE)" ./cmd/fakets
ls -l ../tailscale-audit.exe ../tailscale-audit-arm64.exe ../tailscale-audit-linux-amd64
