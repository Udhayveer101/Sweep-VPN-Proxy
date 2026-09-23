#!/bin/bash
# Build Sweep VPN for Windows: the patched usque (same pinned commit and patches
# as the Mac build) embedded in one tray app.
#   Windows/build.sh [version]   ->  Windows/dist/SweepVPN-<version>-windows-x64.exe
set -euo pipefail
VERSION="${1:-dev}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PATCHES="$HERE/../Tools/usque"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$WORK" init -q
git -C "$WORK" remote add origin https://github.com/Diniboy1123/usque
git -C "$WORK" fetch -q --depth 1 origin "$(cat "$PATCHES/BASE_COMMIT")"
git -C "$WORK" checkout -q FETCH_HEAD
git -C "$WORK" -c user.name=ci -c user.email=ci@localhost am -q \
  "$PATCHES/masque-keepalive.patch" "$PATCHES/masque-handshake-timeout.patch" "$PATCHES/masque-closed-pipe.patch" \
  "$PATCHES/flow-standby-rotation.patch" "$PATCHES/darwin-tun-framing.patch" \
  "$PATCHES/standby-backoff.patch" "$PATCHES/standby-age-log.patch"
(cd "$WORK" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$HERE/usque.exe" .)

mkdir -p "$HERE/dist"
OUT="$HERE/dist/SweepVPN-$VERSION-windows-x64.exe"
(cd "$HERE" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o "$OUT" .)
(cd "$HERE/dist" && shasum -a 256 "$(basename "$OUT")" > "$(basename "$OUT").sha256" 2>/dev/null \
  || sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "built $OUT"
