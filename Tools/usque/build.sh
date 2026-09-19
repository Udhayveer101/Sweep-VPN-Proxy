#!/bin/bash
# Build the patched usque that Sweep bundles for WARP. Upstream at a pinned
# commit plus five patches: HTTP/2 PINGs + in-tunnel DNS retry, a 10s bound on
# the MASQUE dial, and ending a session whose HTTP/2 stream closed under a write
# (see WarpController for why). Universal so the release runs on Intel too.
#
# Usage: Tools/usque/build.sh <output-path>
set -euo pipefail
OUT="${1:?usage: build.sh <output-path>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$WORK" init -q
git -C "$WORK" remote add origin https://github.com/Diniboy1123/usque
git -C "$WORK" fetch -q --depth 1 origin "$(cat "$HERE/BASE_COMMIT")"
git -C "$WORK" checkout -q FETCH_HEAD
git -C "$WORK" -c user.name=ci -c user.email=ci@localhost am -q \
  "$HERE/masque-keepalive.patch" "$HERE/masque-handshake-timeout.patch" "$HERE/masque-closed-pipe.patch" \
    "$HERE/flow-standby-rotation.patch" "$HERE/darwin-tun-framing.patch" \
    "$HERE/standby-backoff.patch"

for ARCH in arm64 amd64; do
  (cd "$WORK" && CGO_ENABLED=0 GOOS=darwin GOARCH=$ARCH go build -trimpath -ldflags "-s -w" -o "usque-$ARCH" .)
done
mkdir -p "$(dirname "$OUT")"
lipo -create "$WORK/usque-arm64" "$WORK/usque-amd64" -output "$OUT"
echo "built $OUT"
