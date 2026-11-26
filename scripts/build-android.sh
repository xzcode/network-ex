#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.."&&pwd)"
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
[[ -d "$ANDROID_HOME" ]]||{ echo "Set ANDROID_HOME to an installed Android SDK" >&2;exit 1; }
export ANDROID_HOME
: "${ANDROID_NDK_HOME:=$ANDROID_HOME/ndk/27.2.12479018}"
[[ -d "$ANDROID_NDK_HOME" ]]||{ echo "Install Android NDK 27.2.12479018 or set ANDROID_NDK_HOME" >&2;exit 1; }
export ANDROID_NDK_HOME
export GOTOOLCHAIN=local
for x in go java javac gradle;do command -v "$x" >/dev/null||{ echo "Missing $x" >&2;exit 1; };done
# Pin the native binding tool to the Go 1.23-compatible version.
toolbin="$root/.mobile-tools/bin";mkdir -p "$toolbin" "$root/apps/android/app/libs"
export GOBIN="$toolbin";export PATH="$toolbin:$PATH"
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20240520174638-fa72addaaa1b
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20240520174638-fa72addaaa1b
cd "$root"
gomobile bind -target=android/arm64,android/amd64 -androidapi=26 -o apps/android/app/libs/network-ex-mobile.aar ./pkg/mobile
cd apps/android
gradle --no-daemon :app:assembleDebug
echo "Debug APK: $root/apps/android/app/build/outputs/apk/debug/app-debug.apk"
