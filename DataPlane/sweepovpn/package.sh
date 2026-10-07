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
# macOS only for now (universal when build/deps-x86_64 exists). The iOS slices need OpenSSL, lz4 and fmt
# cross-compiled for ios-arm64 and the simulator, which Homebrew does not
# provide — see the note at the bottom of this file.
set -euo pipefail
cd "$(dirname "$0")"

BREW="${BREW_PREFIX:-/opt/homebrew}"
# build/deps (Tools/build-deps-mac.sh) holds openssl/lz4/fmt built for the app's
# deployment target; Homebrew's static libs only target the host OS.
DEPS="$(cd ../.. && pwd)/build/deps"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
if [ -d "$DEPS/lib" ]; then
  SSL="$DEPS" LZ4="$DEPS" FMT="$DEPS" PREFIXES="$DEPS"
else
  SSL="$BREW/opt/openssl@3" LZ4="$BREW/opt/lz4" FMT="$BREW/opt/fmt" PREFIXES="$BREW"
fi
BUILD="build-mac"
OUT="../SweepOpenVPN.xcframework"
STAGE="build-stage"

if [ ! -d ../openvpn/openvpn3 ]; then
  echo "openvpn3 missing — run ../openvpn/fetch.sh first" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/mac"
SLICES=()
build_slice() { # arch, deps prefix (ssl/lz4/fmt), cmake prefix path
  local arch="$1" ssl="$2" lz4="$3" fmt="$4" prefixes="$5"
  echo "==> building $arch"
  cmake -S . -B "$BUILD-$arch" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$arch" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
    -DCMAKE_PREFIX_PATH="$prefixes" \
    -DOPENSSL_ROOT_DIR="$ssl" >/dev/null
  cmake --build "$BUILD-$arch" --target sweepovpn >/dev/null
  libtool -static -o "$STAGE/mac/libsweepovpn-$arch.a" \
    "$BUILD-$arch/libsweepovpn.a" \
    "$ssl/lib/libssl.a" \
    "$ssl/lib/libcrypto.a" \
    "$lz4/lib/liblz4.a" \
    "$fmt/lib/libfmt.a" 2>/dev/null
  SLICES+=("$STAGE/mac/libsweepovpn-$arch.a")
}
build_slice arm64 "$SSL" "$LZ4" "$FMT" "$PREFIXES"
# Intel slice: needs `ARCH=x86_64 Tools/build-deps-mac.sh` (Homebrew on Apple
# Silicon has no x86_64 libs). asio and xxhash are headers, so brew's serve both.
if [ -d "$DEPS-x86_64/lib" ]; then
  build_slice x86_64 "$DEPS-x86_64" "$DEPS-x86_64" "$DEPS-x86_64" "$DEPS-x86_64;$BREW"
fi
lipo -create "${SLICES[@]}" -output "$STAGE/mac/libsweepovpn.a"
rm -f "${SLICES[@]}"

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
