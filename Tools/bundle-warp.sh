#!/bin/bash
# Copy the WARP payload — usque and gaming mode's privileged script — into an
# .app bundle and re-sign it.
#
# This was bundle-tor.sh, which also carried tor, obfs4proxy, snowflake-client,
# meek-client and tor's whole Homebrew dylib closure. Tor was retired from the
# app (it was mutually exclusive with WARP and unreachable on the network this
# is built for), so all of that is gone and the release is tens of megabytes
# smaller.
#
# Usage: bundle-warp.sh <App.app> [signing-identity]
set -euo pipefail

APP="${1:?usage: bundle-warp.sh <App.app> [identity]}"
IDENTITY="${2:--}"
# Notarization needs a secure timestamp on every binary; local builds skip the
# network round trip. The release workflow sets SIGN_TIMESTAMP=--timestamp.
TS="${SIGN_TIMESTAMP:---timestamp=none}"
# Apple's timestamp service intermittently answers "not available"; retry.
sign() { for i in 1 2 3 4 5; do codesign "$@" && return 0; sleep $((i * 3)); done; return 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$APP/Contents/Resources/warp"

# Drop a previous build's tor payload so an upgrade does not keep shipping it.
rm -rf "$APP/Contents/Resources/tor"

# usque (WARP over MASQUE), built from the pinned + patched tree by
# Tools/usque/build.sh. Build it there rather than from upstream: the patches
# are what make the HTTP/2 path survive this network.
USQUE="${USQUE:-$HOME/src/usque/usque}"
if [ -x "$USQUE" ]; then
  mkdir -p "$DEST"
  cp -f "$USQUE" "$DEST/usque"
  chmod u+w "$DEST/usque"
  sign --force "$TS" --options runtime --sign "$IDENTITY" "$DEST/usque"
  # Gaming mode's privileged half. It runs under the system's authorization
  # dialog (or osascript as a fallback), so it is a script rather than a signed
  # helper: a Developer ID app cannot install a privileged helper without the
  # paid NE entitlement.
  cp -f "$HERE/gamemode.sh" "$DEST/gamemode.sh"
  chmod 755 "$DEST/gamemode.sh"
else
  echo "warning: usque not found at $USQUE; WARP mode is unavailable" >&2
  echo "         build it with: Tools/usque/build.sh $USQUE" >&2
fi

# The app was signed before these files existed, so its seal no longer covers
# Contents/Resources. Without re-sealing, `codesign --verify` reports "a sealed
# resource is missing or invalid" and the OS refuses to launch it. Entitlements
# are preserved from the existing signature — re-signing without them would
# strip the NetworkExtension capability and put us back at "permission denied".
sign --force "$TS" --sign "$IDENTITY" \
  --preserve-metadata=entitlements,requirements,flags,runtime "$APP"
codesign --verify --deep --strict "$APP" || {
  echo "re-signing failed; the app will not launch" >&2
  exit 1
}

echo "bundled WARP -> $DEST"
