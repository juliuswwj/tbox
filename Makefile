# tbox build.
#
# sing-box REALITY requires the `with_utls` build tag, and a Go toolchain
# >= 1.24.7 (set GO to your toolchain if `go` on PATH is older).

GO ?= go
#$XBH_AI_PATCH_START
#TAGS := with_utls
#$XBH_AI_PATCH_MODIFY
#TAGS := with_utls with_clash_api
#$XBH_AI_PATCH_MODIFY
TAGS := with_utls with_clash_api with_quic
#$XBH_AI_PATCH_END
BIN := bin/tbox

# Android client (gomobile). ANDROID_HOME and ANDROID_NDK_HOME must be set, and
# `gomobile`/`gobind` must be on PATH (see `android-tools`). The tbox.aar bundles
# our ./mobile helper together with sing-box's experimental/libbox runtime.
ANDROID_AAR := android/app/libs/tbox.aar
ANDROID_PKG := com.juliuswwj.tbox
GOMOBILE ?= gomobile

.PHONY: build test vet tidy clean run-server run-client android android-apk android-tools

build:
	$(GO) build -tags '$(TAGS)' -o $(BIN) ./cmd/tbox

test:
	$(GO) test -tags '$(TAGS)' ./...

# End-to-end test makes a real REALITY handshake to www.microsoft.com:443
# (needs outbound internet).
test-e2e:
	$(GO) test -tags '$(TAGS)' -v -run TestEndToEnd ./internal/integration/

vet:
	$(GO) vet -tags '$(TAGS)' ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin $(ANDROID_AAR)

# Install the gomobile toolchain (one-time). Requires the Android NDK.
android-tools:
	$(GO) install golang.org/x/mobile/cmd/gomobile@latest
	$(GO) install golang.org/x/mobile/cmd/gobind@latest
	$(GOMOBILE) init

# Build the Android AAR. Bundles ./mobile (token + tun config, reusing internal/
# token & singbox) and sing-box's libbox runtime. REALITY needs the with_utls tag.
#
# -checklinkname=0: sing-box's libbox uses //go:linkname to reach os.checkPidfdOnce
# (a workaround for golang/go#70508); Go >= 1.23 rejects that reference unless the
# linker check is disabled.
android:
	$(GOMOBILE) bind -tags '$(TAGS)' -target=android -androidapi 24 \
		-ldflags '-checklinkname=0' \
		-javapkg $(ANDROID_PKG) -o $(ANDROID_AAR) \
		./mobile github.com/sagernet/sing-box/experimental/libbox
	@echo "built $(ANDROID_AAR); now: cd android && ./gradlew assembleDebug"

# Build the debug APK in one shot. Requires the AAR to be present (run
# `make android` first, or use the combined `android-apk` target which does
# both).
ANDROID_APK := android/app/build/outputs/apk/debug/app-debug.apk

android-apk: android
	cd android && ./gradlew assembleDebug
	@echo "built $(ANDROID_APK)"
