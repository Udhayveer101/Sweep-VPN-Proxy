#!/bin/bash
# Build the iOS app, sign it for the App Store, and upload it to TestFlight.
#
# There is no CI for this: the packet-tunnel entitlement needs a paid team, and
# `xcodebuild -allowProvisioningUpdates` fails with our ASC key ("Authentication
# failed") even though the REST API works. So signing is manual: the three
# App Store profiles below, resolved per target by bundle identifier.
#
# Env: VERSION / BUILD_NUMBER default to what project.yml already says.
#      ASC_KEY / ASC_ISSUER identify the App Store Connect key.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(sed -n 's/.*MARKETING_VERSION: "\(.*\)"/\1/p' project.yml | head -1)}"
BUILD_NUMBER="${BUILD_NUMBER:-$(sed -n 's/.*CURRENT_PROJECT_VERSION: "\(.*\)"/\1/p' project.yml | head -1)}"
ASC_KEY="${ASC_KEY:-7P82F4LT95}"
ASC_ISSUER="${ASC_ISSUER:-c10ef62a-c354-4eed-bc3c-e61c22e06262}"
KEY_PATH="${KEY_PATH:-$HOME/.appstoreconnect/private_keys/AuthKey_$ASC_KEY.p8}"
OUT="build/ios-testflight"

[ -f "$KEY_PATH" ] || { echo "no ASC key at $KEY_PATH" >&2; exit 1; }

# The profile UUIDs, keyed the way xcodebuild spells a bundle id in a variable
# name. Each target then resolves its own through PROVISIONING_PROFILE_SPECIFIER.
profile() {
    local id="$1"
    for f in "$HOME/Library/MobileDevice/Provisioning Profiles"/*.mobileprovision; do
        local plist; plist=$(security cms -D -i "$f" 2>/dev/null) || continue
        if [ "$(plutil -extract Entitlements.application-identifier raw - <<<"$plist" 2>/dev/null)" = "P66SB4MX92.$id" ]; then
            plutil -extract UUID raw - <<<"$plist"; return 0
        fi
    done
    echo "no App Store profile for $id (make one in the developer portal)" >&2
    return 1
}
PP_APP=$(profile com.sweep.vpn.ios)
PP_TUNNEL=$(profile com.sweep.vpn.ios.tunnel)
PP_WARP=$(profile com.sweep.vpn.ios.warp)

[ -d DataPlane/SweepWarp.xcframework ] || DataPlane/warpmobile/build.sh
rm -rf "$OUT" && mkdir -p "$OUT"
xcodegen generate

xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-iOS -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$OUT/SweepVPN.xcarchive" \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM=P66SB4MX92 \
  CODE_SIGN_IDENTITY="Apple Distribution" \
  'PROVISIONING_PROFILE_SPECIFIER=$(SWEEP_PP_$(PRODUCT_BUNDLE_IDENTIFIER:c99extidentifier))' \
  SWEEP_PP_com_sweep_vpn_ios="$PP_APP" \
  SWEEP_PP_com_sweep_vpn_ios_tunnel="$PP_TUNNEL" \
  SWEEP_PP_com_sweep_vpn_ios_warp="$PP_WARP" \
  archive | tail -3

cat > "$OUT/export.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>P66SB4MX92</string>
  <key>signingStyle</key><string>manual</string>
  <key>provisioningProfiles</key><dict>
    <key>com.sweep.vpn.ios</key><string>Sweep iOS AppStore</string>
    <key>com.sweep.vpn.ios.tunnel</key><string>Sweep iOS Tunnel AppStore</string>
    <key>com.sweep.vpn.ios.warp</key><string>Sweep iOS Warp AppStore</string>
  </dict>
</dict></plist>
PLIST

# altool is broken here ("Defaults.properties couldn't be opened"); exportArchive
# with destination=upload does the same job and works.
xcodebuild -exportArchive -archivePath "$OUT/SweepVPN.xcarchive" \
  -exportOptionsPlist "$OUT/export.plist" -exportPath "$OUT/export" \
  -authenticationKeyPath "$KEY_PATH" \
  -authenticationKeyID "$ASC_KEY" \
  -authenticationKeyIssuerID "$ASC_ISSUER" | tail -5

echo "uploaded $VERSION ($BUILD_NUMBER) to App Store Connect"
