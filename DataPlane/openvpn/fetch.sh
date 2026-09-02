#!/usr/bin/env bash
# Fetch the vendored OpenVPN 3 source. Not committed: it is 14 MB of upstream
# code with its own history, and pinning the commit here keeps the build
# reproducible without carrying a copy in this repo.
#
# TLS is OpenSSL rather than mbedTLS. mbedTLS would be lighter for the
# extension's memory budget, but Homebrew now ships mbedTLS 4.x, which this
# openvpn3 does not build against yet. Revisit when it does.
set -euo pipefail
cd "$(dirname "$0")"
COMMIT=7f572f4fe647a36f5a1094cbeb261a5bcdae5047
if [ ! -d openvpn3 ]; then
  git clone https://github.com/OpenVPN/openvpn3.git
fi
cd openvpn3
git fetch --depth 50 origin
git checkout -q "$COMMIT"
echo "openvpn3 at $COMMIT"
