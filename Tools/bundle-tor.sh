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
        QUEUE="$QUEUE|$DEST/$BASE"
        ;;
    esac
    install_name_tool -change "$LIB" "@loader_path/$BASE" "$CUR"
  done
done

# obfs4proxy is a static Go binary with no non-system dylibs, so it only needs
# copying. Without it Tor cannot use bridges, and on networks that block Tor
# outright (observed: CONNECTRESET at 14% bootstrap from an Indian ISP) a direct
# connection never completes.
OBFS4="$(command -v obfs4proxy || echo /opt/homebrew/bin/obfs4proxy)"
if [ -x "$OBFS4" ]; then
  cp -f "$OBFS4" "$DEST/obfs4proxy"
  chmod u+w "$DEST/obfs4proxy"
  codesign --force --timestamp=none --options runtime --sign "$IDENTITY" "$DEST/obfs4proxy"
else
  echo "warning: obfs4proxy not found; bridges will be unavailable (brew install obfs4proxy)" >&2
fi

# Sign inside-out: dylibs first, then the executable that loads them.
for F in "$DEST"/*.dylib; do
  [ -e "$F" ] || continue
  codesign --force --timestamp=none --sign "$IDENTITY" "$F"
done
codesign --force --timestamp=none --options runtime --sign "$IDENTITY" "$DEST/tor"

echo "bundled tor -> $DEST"
otool -L "$DEST/tor" | tail -n +2 | awk '{print "  " $1}'
