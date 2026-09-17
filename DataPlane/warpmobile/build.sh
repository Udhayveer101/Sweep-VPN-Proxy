#!/bin/bash
# Build SweepWarp.xcframework: the iOS WARP data plane (main.go) compiled as a
# C archive inside the same pinned, patched usque tree Tools/usque/build.sh
# builds the macOS binary from, so both platforms run identical tunnel code.
#
# Usage: DataPlane/warpmobile/build.sh      (needs Go and Xcode)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PATCHES="$ROOT/Tools/usque"
OUT="$ROOT/DataPlane/SweepWarp.xcframework"
MIN_IOS=17.0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$WORK" init -q
git -C "$WORK" remote add origin https://github.com/Diniboy1123/usque
git -C "$WORK" fetch -q --depth 1 origin "$(cat "$PATCHES/BASE_COMMIT")"
git -C "$WORK" checkout -q FETCH_HEAD
git -C "$WORK" -c user.name=ci -c user.email=ci@localhost am -q \
  "$PATCHES/masque-keepalive.patch" "$PATCHES/masque-handshake-timeout.patch" "$PATCHES/masque-closed-pipe.patch" \
    "$PATCHES/flow-standby-rotation.patch" "$PATCHES/darwin-tun-framing.patch"
mkdir -p "$WORK/sweepwarp" && cp "$HERE/main.go" "$HERE/main_test.go" "$WORK/sweepwarp/"
(cd "$WORK" && go vet ./sweepwarp && go test ./sweepwarp)

build() { # <sdk> <clang target> <out dir>
  local sdk="$1" target="$2" dir="$WORK/out/$3"
  mkdir -p "$dir"
  (cd "$WORK" && CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
    CC="$(xcrun -sdk "$sdk" -f clang)" \
    CGO_CFLAGS="-isysroot $(xcrun -sdk "$sdk" --show-sdk-path) -target $target -fembed-bitcode=off" \
    CGO_LDFLAGS="-isysroot $(xcrun -sdk "$sdk" --show-sdk-path) -target $target" \
    go build -buildmode=c-archive -trimpath -ldflags "-s -w" -o "$dir/libsweepwarp.a" ./sweepwarp)
  # A subfolder, not the Headers root: every xcframework's module.modulemap
  # lands in the same include/ directory, and two at the root collide.
  mkdir -p "$dir/Headers/SweepWarpC"
  mv "$dir/libsweepwarp.h" "$dir/Headers/SweepWarpC/sweepwarp.h"
  printf 'module SweepWarpC {\n    header "sweepwarp.h"\n    export *\n}\n' > "$dir/Headers/SweepWarpC/module.modulemap"
}
build iphoneos "arm64-apple-ios$MIN_IOS" device
build iphonesimulator "arm64-apple-ios$MIN_IOS-simulator" simulator

rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$WORK/out/device/libsweepwarp.a" -headers "$WORK/out/device/Headers" \
  -library "$WORK/out/simulator/libsweepwarp.a" -headers "$WORK/out/simulator/Headers" \
  -output "$OUT"
echo "built $OUT"
