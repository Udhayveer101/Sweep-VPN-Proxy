#!/bin/bash
# Build tor and the native libraries the macOS app links or bundles, pinned to
# the app's deployment target. Homebrew only bottles for the host OS (Tahoe), so
# its tor and static libs are stamped minos 26 and dyld refuses them on Sequoia.
#
# Output: build/deps/{bin,lib,include}. bundle-tor.sh and sweepovpn/package.sh
# use it when it exists (TOR_PREFIX / BREW_PREFIX).
set -euo pipefail
cd "$(dirname "$0")/.."

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
export CFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET -O2"
export CXXFLAGS="$CFLAGS" LDFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
PREFIX="$PWD/build/deps"
SRC="$PWD/build/deps-src"
JOBS="$(sysctl -n hw.ncpu)"
mkdir -p "$PREFIX" "$SRC"

# Sources come from Homebrew's mirrors (same versions it ships). tor's only
# origin is dist.torproject.org, which some networks intercept; set
# DEPS_PROXY=127.0.0.1:1081 to fetch it through the app's WARP SOCKS port.
unpack() { # formula -> prints source dir
  brew fetch -s "$1" >/dev/null
  local t; t="$(brew --cache -s "$1")"
  local d="$SRC/$1"; rm -rf "$d"; mkdir -p "$d"
  case "$t" in *.zip) ditto -x -k "$t" "$d";; *) tar -xzf "$t" -C "$d";; esac
  echo "$d/$(ls "$d" | head -1)"
}

D=$(unpack openssl@3)
(cd "$D" && ./Configure darwin64-arm64-cc no-tests no-shared \
   --prefix="$PREFIX" --libdir=lib && make -j"$JOBS" && make install_sw) >/dev/null

D=$(unpack libevent)
(cd "$D" && ./configure --prefix="$PREFIX" --disable-samples \
   --disable-openssl --disable-shared && make -j"$JOBS" install) >/dev/null

TOR=0.4.9.11
[ -f "$SRC/tor.tgz" ] || curl -fsSL ${DEPS_PROXY:+--socks5-hostname "$DEPS_PROXY"} \
  -o "$SRC/tor.tgz" "https://dist.torproject.org/tor-$TOR.tar.gz"
rm -rf "$SRC/tor-$TOR" && tar -xzf "$SRC/tor.tgz" -C "$SRC"
# Static openssl/libevent: the bundled tor then needs no dylibs at all.
(cd "$SRC/tor-$TOR" && ./configure --prefix="$PREFIX" --with-openssl-dir="$PREFIX" \
   --with-libevent-dir="$PREFIX" --enable-static-openssl --enable-static-libevent \
   --disable-asciidoc --disable-manpage --disable-html-manual --disable-lzma \
   --disable-zstd --disable-unittests && make -j"$JOBS" install) >/dev/null

D=$(unpack lz4)
(cd "$D" && make -j"$JOBS" -C lib liblz4.a && cp lib/liblz4.a "$PREFIX/lib/" \
   && cp lib/lz4.h lib/lz4hc.h lib/lz4frame.h "$PREFIX/include/") >/dev/null

D=$(unpack fmt)
(cmake -S "$D" -B "$SRC/fmt-build" -GNinja -DCMAKE_BUILD_TYPE=Release \
   -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" -DFMT_TEST=OFF -DFMT_DOC=OFF \
   -DCMAKE_INSTALL_PREFIX="$PREFIX" && cmake --build "$SRC/fmt-build" --target install) >/dev/null

echo "deps -> $PREFIX (minos $MACOSX_DEPLOYMENT_TARGET)"
