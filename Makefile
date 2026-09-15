export PATH := /opt/homebrew/opt/rustup/bin:$(PATH)
RUSTUP :=
LOCAL  := Config/Local.xcconfig
# Signing identity and team come from your own Config/Local.xcconfig, not from
# the repo. Override on the command line if you keep them somewhere else.
TEAM   ?= $(shell sed -n 's/^[[:space:]]*DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*//p' $(LOCAL) 2>/dev/null)
CRATE  := DataPlane/sweepwg
TARGETS := aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

.PHONY: config dataplane warp-ios test project ios ios-ipa macos install-macos bundle-tor release

# First thing to run after cloning. Creates the gitignored file that holds your
# team, your pinned key and your own Worker.
config:
	@if [ -f $(LOCAL) ]; then echo "$(LOCAL) already exists, leaving it alone"; \
	else cp $(LOCAL).example $(LOCAL); echo "created $(LOCAL) - fill it in"; fi

dataplane:
	cd $(CRATE) && $(RUSTUP) $(foreach t,$(TARGETS),cargo build --release --target $(t) &&) true
	cd $(CRATE) && mkdir -p fat/sim fat/mac && \
	  lipo -create target/aarch64-apple-ios-sim/release/libsweepwg.a target/x86_64-apple-ios/release/libsweepwg.a -output fat/sim/libsweepwg.a && \
	  lipo -create target/aarch64-apple-darwin/release/libsweepwg.a target/x86_64-apple-darwin/release/libsweepwg.a -output fat/mac/libsweepwg.a
	rm -rf DataPlane/SweepWireGuard.xcframework
	xcodebuild -create-xcframework \
	  -library $(CRATE)/target/aarch64-apple-ios/release/libsweepwg.a -headers $(CRATE)/include \
	  -library $(CRATE)/fat/sim/libsweepwg.a -headers $(CRATE)/include \
	  -library $(CRATE)/fat/mac/libsweepwg.a -headers $(CRATE)/include \
	  -output DataPlane/SweepWireGuard.xcframework

test:
	cd Core && swift test
	cd Kit && swift test
	cd $(CRATE) && $(RUSTUP) cargo test --release

project: $(LOCAL)
	xcodegen generate

$(LOCAL):
	@$(MAKE) config

warp-ios:
	DataPlane/warpmobile/build.sh

ios-ipa:
	Tools/release-ios.sh

ios: project
	xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-iOS -sdk iphonesimulator ARCHS=arm64 \
	  -destination 'generic/platform=iOS Simulator' CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO build

# NetworkExtension entitlements cannot be ad-hoc signed: xcodebuild rejects the
# build outright ("entitlements that require signing with a development
# certificate"), and even if it did not, the system-extension daemon refuses an
# unsigned bundle. This is the real cause of the "permission denied" at connect
# time, so the macOS target signs for real.
macos: project
	xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS -destination 'platform=macOS' \
	  -allowProvisioningUpdates CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM=$(TEAM) build

# Install where OSSystemExtensionManager will accept it. Activation requests
# from an app outside /Applications are rejected before they reach the daemon.
# Tor ships inside the app; see Tools/bundle-tor.sh for why the dylibs must be
# rewritten. Signed with the development identity so the bundle stays valid.
# Whichever development identity this Mac holds. Set SIGN_ID yourself if you
# have more than one and want a particular certificate.
SIGN_ID ?= $(shell security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development: .*\)"/\1/p' | head -1)

bundle-tor:
	@APP=$$(xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS \
	    -destination 'platform=macOS' -showBuildSettings 2>/dev/null \
	    | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{d=$$2} / FULL_PRODUCT_NAME /{n=$$2} END{print d"/"n}'); \
	  ./Tools/bundle-tor.sh "$$APP" "$(SIGN_ID)"

install-macos: macos bundle-tor
	@APP=$$(xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS \
	    -destination 'platform=macOS' -showBuildSettings 2>/dev/null \
	    | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{d=$$2} / FULL_PRODUCT_NAME /{n=$$2} END{print d"/"n}'); \
	  echo "installing $$APP -> /Applications"; \
	  rm -rf "/Applications/$$(basename $$APP)"; \
	  cp -R "$$APP" /Applications/; \
	  codesign -dv "/Applications/$$(basename $$APP)" 2>&1 | head -3

# Signed + notarized DMG, built on this Mac like Sweep's releases. Uses the
# Developer ID identity in the login keychain and the `sweep-notary` notarytool
# profile; publish with `gh release create vX build/release/SweepVPN-X.dmg*`.
release:
	VERSION=$(VERSION) TEAM_ID=$(TEAM) NOTARY_PROFILE=$${NOTARY_PROFILE:-sweep-notary} \
	  SWEEP_CONFIG_SIGNING_KEY=$$(sed -n 's/^[[:space:]]*SWEEP_CONFIG_SIGNING_KEY[[:space:]]*=[[:space:]]*//p' $(LOCAL)) \
	  Tools/release-macos.sh
