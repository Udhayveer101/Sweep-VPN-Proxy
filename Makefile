export PATH := /opt/homebrew/opt/rustup/bin:$(PATH)
RUSTUP :=
CRATE  := DataPlane/sweepwg
TARGETS := aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

.PHONY: dataplane test project ios macos

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

macos: project
	xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-macOS -destination 'platform=macOS' \
	  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO build
