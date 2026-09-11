#!/bin/bash
# Copy the tor binary and its non-system dylibs into an .app bundle, rewrite the
# load paths to @loader_path, and re-sign. Homebrew's tor links against dylibs in
# /opt/homebrew, which will not exist on any other machine and are outside the
# app sandbox, so the binary is unusable until its references are rewritten.
#
# Usage: bundle-tor.sh <App.app> [signing-identity]
set -euo pipefail

APP="${1:?usage: bundle-tor.sh <App.app> [identity]}"
IDENTITY="${2:--}"
SRC="$(command -v tor || echo /opt/homebrew/bin/tor)"
DEST="$APP/Contents/Resources/tor"

[ -x "$SRC" ] || { echo "tor not found; run: brew install tor" >&2; exit 1; }

mkdir -p "$DEST"
cp -f "$SRC" "$DEST/tor"
chmod u+w "$DEST/tor"

# Resolve the dependency closure: tor's own dylibs, plus what those dylibs need.
resolve() {
  otool -L "$1" | tail -n +2 | awk '{print $1}' \
    | grep -E '^/(opt/homebrew|usr/local)' || true
}

# macOS ships bash 3.2, which has no associative arrays — a plain seen-list works.
SEEN=""
QUEUE="$DEST/tor"
while [ -n "$QUEUE" ]; do
  CUR="${QUEUE%%|*}"
  case "$QUEUE" in *\|*) QUEUE="${QUEUE#*|}";; *) QUEUE="";; esac
  # Appending to an emptied queue leaves a leading "|", which yields an empty
  # entry on the next pass; otool would then fail on a nonexistent path.
  [ -n "$CUR" ] || continue
  for LIB in $(resolve "$CUR"); do
    BASE="$(basename "$LIB")"
    case "|$SEEN|" in
      *"|$BASE|"*) ;;
      *)
        SEEN="$SEEN|$BASE"
        cp -f "$LIB" "$DEST/$BASE"
        chmod u+w "$DEST/$BASE"
        # A dylib's own id must point at the bundled copy too.
        install_name_tool -id "@loader_path/$BASE" "$DEST/$BASE"
        QUEUE="${QUEUE:+$QUEUE|}$DEST/$BASE"
        ;;
    esac
    install_name_tool -change "$LIB" "@loader_path/$BASE" "$CUR"
  done
done

# obfs4proxy is a static Go binary with no non-system dylibs, so it only needs
# copying. Without it Tor cannot use bridges, and on networks that block Tor
# outright (observed: CONNECTRESET at 14% bootstrap from an Indian ISP) a direct
# connection never completes.
# obfs4proxy handles both obfs4 and meek_lite; snowflake-client is separate.
# All are static Go binaries with no non-system dylibs, so they only need
# copying. Each is a step in the fallback chain: on networks that block Tor
# outright a direct bootstrap never completes.
for T in obfs4proxy snowflake-client meek-client; do
  SRC_T="$(command -v "$T" || echo "/opt/homebrew/bin/$T")"
  if [ -x "$SRC_T" ]; then
    cp -f "$SRC_T" "$DEST/$T"
    chmod u+w "$DEST/$T"
    codesign --force --timestamp=none --options runtime --sign "$IDENTITY" "$DEST/$T"
  else
    echo "warning: $T not found; that transport is unavailable (brew install $T)" >&2
  fi
done

# Sign inside-out: dylibs first, then the executable that loads them.
for F in "$DEST"/*.dylib; do
  [ -e "$F" ] || continue
  codesign --force --timestamp=none --sign "$IDENTITY" "$F"
done
codesign --force --timestamp=none --options runtime --sign "$IDENTITY" "$DEST/tor"

# usque (WARP over MASQUE) is a static Go binary built from source:
#   git clone https://github.com/Diniboy1123/usque && CGO_ENABLED=0 go build
# Optional — without it the WARP toggle says the binary is missing.
USQUE="${USQUE:-$HOME/src/usque/usque}"
if [ -x "$USQUE" ]; then
  mkdir -p "$APP/Contents/Resources/warp"
  cp -f "$USQUE" "$APP/Contents/Resources/warp/usque"
  chmod u+w "$APP/Contents/Resources/warp/usque"
  codesign --force --timestamp=none --options runtime --sign "$IDENTITY" \
    "$APP/Contents/Resources/warp/usque"
else
  echo "warning: usque not found at $USQUE; WARP mode is unavailable" >&2
fi

# The app was signed before these files existed, so its seal no longer covers
# Contents/Resources. Without re-sealing, `codesign --verify` reports "a sealed
# resource is missing or invalid" and the OS refuses to launch it. Entitlements
# are preserved from the existing signature — re-signing without them would
# strip the NetworkExtension capability and put us back at "permission denied".
codesign --force --sign "$IDENTITY" \
  --preserve-metadata=entitlements,requirements,flags,runtime "$APP"
codesign --verify --deep --strict "$APP" || {
  echo "re-signing failed; the app will not launch" >&2
  exit 1
}

echo "bundled tor -> $DEST"
otool -L "$DEST/tor" | tail -n +2 | awk '{print "  " $1}'
