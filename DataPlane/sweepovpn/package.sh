#!/usr/bin/env bash
# Build DataPlane/SweepOpenVPN.xcframework from the shim plus everything it
# links, as one self-contained static archive per platform slice.
#
# Why a merged archive: Swift's `.binaryTarget` takes a library, not a library
# plus a list of things to find later. If the slice referenced Homebrew dylibs
# the app would only run on a Mac with the same Homebrew prefix, and could not
# run on iOS at all. `libtool -static` folds OpenSSL, lz4 and fmt in so the
# framework carries its own dependencies.
#
# macOS arm64 only for now. The iOS slices need OpenSSL, lz4 and fmt
# cross-compiled for ios-arm64 and the simulator, which Homebrew does not
# provide — see the note at the bottom of this file.
set -euo pipefail
cd "$(dirname "$0")"

BREW="${BREW_PREFIX:-/opt/homebrew}"
BUILD="build-mac"
OUT="../SweepOpenVPN.xcframework"
STAGE="build-stage"

if [ ! -d ../openvpn/openvpn3 ]; then
  echo "openvpn3 missing — run ../openvpn/fetch.sh first" >&2
  exit 1
fi

echo "==> configuring"
cmake -S . -B "$BUILD" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$BREW" \
  -DOPENSSL_ROOT_DIR="$BREW/opt/openssl@3" >/dev/null

echo "==> building"
cmake --build "$BUILD" --target sweepovpn >/dev/null

echo "==> merging static dependencies"
rm -rf "$STAGE"
mkdir -p "$STAGE/mac"
libtool -static -o "$STAGE/mac/libsweepovpn.a" \
  "$BUILD/libsweepovpn.a" \
  "$BREW/opt/openssl@3/lib/libssl.a" \
  "$BREW/opt/openssl@3/lib/libcrypto.a" \
  "$BREW/opt/lz4/lib/liblz4.a" \
  "$BREW/opt/fmt/lib/libfmt.a" 2>/dev/null

# The headers directory name ends up in the framework's search paths, and
# SweepWireGuard.xcframework already ships one called "include". Two of those
# means two module.modulemap files at the same path, which Xcode rejects as
# "multiple commands produce". Hence a distinct name.
mkdir -p "$STAGE/headers/SweepOpenVPNC"
cp include/sweepovpn.h "$STAGE/headers/SweepOpenVPNC/"
cat > "$STAGE/headers/SweepOpenVPNC/module.modulemap" <<'MAP'
module SweepOpenVPNC {
    header "sweepovpn.h"
    export *
}
MAP

echo "==> assembling xcframework"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$STAGE/mac/libsweepovpn.a" -headers "$STAGE/headers" \
  -output "$OUT" >/dev/null

echo "built $OUT"
lipo -info "$STAGE/mac/libsweepovpn.a" 2>/dev/null || true

# iOS: OpenSSL, lz4 and fmt all need building for ios-arm64 and
# ios-arm64-simulator before a slice can be added here. openvpn3 itself is
# almost entirely headers and defines USE_TUN_BUILDER automatically on iOS, so
# the shim needs no source change — only its dependencies do.
