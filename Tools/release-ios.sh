#!/bin/bash
# Build the iOS WARP app as an unsigned IPA (build/ios/SweepVPN-<version>.ipa).
#
# The IPA carries its entitlements in an ad-hoc signature so that re-signing
# tools keep them. It still has to be signed by an Apple Developer Program team
# before it will install: iOS only grants the packet-tunnel entitlement WARP
# runs in to paid teams, never to a free Apple ID.
#
# Env: VERSION (default 1.0), BUILD_NUMBER (default 1)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-1.0}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
OUT="build/ios"
rm -rf "$OUT" && mkdir -p "$OUT"

[ -d DataPlane/SweepWarp.xcframework ] || DataPlane/warpmobile/build.sh

# Like the macOS release: ship nothing personal from Config/Local.xcconfig.
[ -f Config/Local.xcconfig ] && cp Config/Local.xcconfig "$OUT/Local.xcconfig.bak"
printf 'SWEEP_CONFIG_SIGNING_KEY = %s\n' "${SWEEP_CONFIG_SIGNING_KEY:-}" > Config/Local.xcconfig
restore() { [ -f "$OUT/Local.xcconfig.bak" ] && mv "$OUT/Local.xcconfig.bak" Config/Local.xcconfig || true; }
trap restore EXIT

xcodegen generate
xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-iOS -configuration Release \
  -destination 'generic/platform=iOS' -derivedDataPath "$OUT/dd" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD_NUMBER" build | tail -3

APP="$OUT/dd/Build/Products/Release-iphoneos/SweepVPN-iOS.app"
[ -d "$APP" ] || { echo "build produced no app" >&2; exit 1; }

# Resolve $(AppIdentifierPrefix) to a placeholder team; re-signing replaces it.
ents() { sed 's/\$(AppIdentifierPrefix)/TEAMID./g' "$1" > "$OUT/$(basename "$(dirname "$1")").entitlements"; echo "$OUT/$(basename "$(dirname "$1")").entitlements"; }
codesign -f -s - --entitlements "$(ents Apps/iOSTunnel/Tunnel.entitlements)" "$APP/PlugIns/SweepVPN-iOS-Tunnel.appex"
codesign -f -s - --entitlements "$(ents Apps/iOSWarp/Tunnel.entitlements)" "$APP/PlugIns/SweepWarpTunnel.appex"
codesign -f -s - --entitlements "$(ents Apps/iOS/App.entitlements)" "$APP"

mkdir -p "$OUT/Payload" && cp -R "$APP" "$OUT/Payload/"
IPA="$OUT/SweepVPN-$VERSION.ipa"
(cd "$OUT" && zip -qry "$(basename "$IPA")" Payload)
shasum -a 256 "$IPA" > "$IPA.sha256"
rm -rf "$OUT/Payload" "$OUT"/*.entitlements
echo "built $IPA"
