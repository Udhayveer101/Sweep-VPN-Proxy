export PATH := /opt/homebrew/opt/rustup/bin:$(PATH)
RUSTUP :=
TEAM   := P66SB4MX92
CRATE  := DataPlane/sweepwg
TARGETS := aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

.PHONY: dataplane test project ios macos install-macos

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

project:
	xcodegen generate

ios: project
	xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-iOS -sdk iphonesimulator \
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
install-macos: macos
	@APP=$$(xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS \
	    -destination 'platform=macOS' -showBuildSettings 2>/dev/null \
	    | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{d=$$2} / FULL_PRODUCT_NAME /{n=$$2} END{print d"/"n}'); \
	  echo "installing $$APP -> /Applications"; \
	  rm -rf "/Applications/$$(basename $$APP)"; \
	  cp -R "$$APP" /Applications/; \
	  codesign -dv "/Applications/$$(basename $$APP)" 2>&1 | head -3
