#!/bin/bash
# Build the Developer ID release: archive the proxy-only app, bundle tor and the
# patched usque (Apple Silicon only: the OpenVPN slice is arm64), sign everything with a secure timestamp, notarize, staple, and
# wrap it in a DMG. The same script runs locally and in .github/workflows.
#
# Env:
#   VERSION            marketing version, e.g. 1.2.0            (required)
#   BUILD_NUMBER       CFBundleVersion                           (default 1)
#   TEAM_ID            Apple team id                             (required)
#   SWEEP_CONFIG_SIGNING_KEY  pinned public key                  (optional)
#   NOTARY_PROFILE     notarytool keychain profile, e.g. sweep-notary (local releases)
#   ASC_KEY_PATH ASC_KEY_ID ASC_ISSUER_ID  notarytool API key    (CI; neither set = not notarized)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${VERSION:?set VERSION}"
: "${TEAM_ID:?set TEAM_ID}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
OUT="build/release"
ARCHIVE="$OUT/Sweep.xcarchive"
rm -rf "$OUT" && mkdir -p "$OUT"

IDENTITY="$(security find-identity -v -p codesigning \
  | sed -n "s/.*\"\(Developer ID Application: .*($TEAM_ID)\)\"/\1/p" | head -1)"
[ -n "$IDENTITY" ] || { echo "no Developer ID Application identity for team $TEAM_ID in the keychain" >&2; exit 1; }
echo "signing as: $IDENTITY"

# The project reads Config/Local.xcconfig; a release gets only what is safe to
# ship. No Worker URL or token: a shared Worker would put everyone's traffic
# on one account, and users paste their own in the app.
[ -f Config/Local.xcconfig ] && cp Config/Local.xcconfig "$OUT/Local.xcconfig.bak"
cat > Config/Local.xcconfig <<EOF
DEVELOPMENT_TEAM = $TEAM_ID
SWEEP_CONFIG_SIGNING_KEY = ${SWEEP_CONFIG_SIGNING_KEY:-}
EOF
restore() { [ -f "$OUT/Local.xcconfig.bak" ] && mv "$OUT/Local.xcconfig.bak" Config/Local.xcconfig || true; }
trap restore EXIT

xcodegen generate
xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS-Direct -configuration Release \
  -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" archive \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$IDENTITY" DEVELOPMENT_TEAM="$TEAM_ID" \
  OTHER_CODE_SIGN_FLAGS=--timestamp ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD_NUMBER" | tail -5

APP="$ARCHIVE/Products/Applications/Sweep VPN.app"
[ -d "$APP" ] || { echo "archive produced no app" >&2; exit 1; }

Tools/usque/build.sh "$OUT/usque"
USQUE="$OUT/usque" SIGN_TIMESTAMP=--timestamp Tools/bundle-tor.sh "$APP" "$IDENTITY"

codesign --verify --deep --strict --verbose=2 "$APP"
if codesign -d --entitlements - "$APP" 2>/dev/null | grep -q get-task-allow; then
  echo "release carries get-task-allow; notarization would reject it" >&2; exit 1
fi

if [ -n "${NOTARY_PROFILE:-}" ]; then
  AUTH=(--keychain-profile "$NOTARY_PROFILE")
else
  AUTH=(--key "${ASC_KEY_PATH:-}" --key-id "${ASC_KEY_ID:-}" --issuer "${ASC_ISSUER_ID:-}")
fi
notarize() {
  # Submit, then poll by id ourselves: `--wait` aborts on a single network
  # timeout while Apple is still processing (seen on the first 1.0.0 run).
  local sid="" status=""
  for i in 1 2 3; do
    sid=$(xcrun notarytool submit "$1" "${AUTH[@]}" --output-format json 2>/dev/null \
      | sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$sid" ] && break; sleep 15
  done
  [ -n "$sid" ] || { echo "notarization upload failed" >&2; exit 1; }
  echo "notary submission $sid"
  for _ in $(seq 1 60); do
    status=$(xcrun notarytool info "$sid" "${AUTH[@]}" --output-format json 2>/dev/null \
      | sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' | head -1)
    case "$status" in Accepted|Invalid|Rejected) break;; esac
    sleep 30
  done
  echo "notary status: ${status:-unknown}"
  if [ "$status" != Accepted ]; then
    xcrun notarytool log "$sid" "${AUTH[@]}" || true
    echo "notarization failed" >&2; exit 1
  fi
}

NOTARIZE=0
[ -n "${NOTARY_PROFILE:-}" ] && NOTARIZE=1
[ -n "${ASC_KEY_PATH:-}" ] && [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER_ID:-}" ] && NOTARIZE=1

if [ $NOTARIZE = 1 ]; then
  ditto -c -k --keepParent "$APP" "$OUT/app.zip"
  notarize "$OUT/app.zip"
  for i in 1 2 3; do xcrun stapler staple "$APP" && break; sleep 10; done
fi

DMG="$OUT/SweepVPN-$VERSION.dmg"
STAGE="$OUT/dmg" && mkdir -p "$STAGE"
ditto "$APP" "$STAGE/Sweep VPN.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Sweep VPN" -srcfolder "$STAGE" -format UDZO -ov "$DMG" >/dev/null
for i in 1 2 3 4 5; do codesign --force --timestamp --sign "$IDENTITY" "$DMG" && break; sleep $((i * 3)); done
codesign --verify --strict "$DMG"

if [ $NOTARIZE = 1 ]; then
  notarize "$DMG"
  for i in 1 2 3; do xcrun stapler staple "$DMG" && break; sleep 10; done
  spctl --assess --type open --context context:primary-signature -v "$DMG"
  spctl --assess --type execute -v "$APP"
else
  echo "warning: no notary credentials; DMG is signed but NOT notarized" >&2
fi
shasum -a 256 "$DMG" | tee "$DMG.sha256"
echo "release: $DMG"
