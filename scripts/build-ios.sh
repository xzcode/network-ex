#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Requires macOS with Xcode and the iOS SDK' >&2;exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
for x in go xcodebuild xcodegen xcrun;do command -v "$x" >/dev/null||{ echo "Missing $x" >&2;exit 1; };done
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path >/dev/null
toolbin="$root/.mobile-tools/bin";mkdir -p "$toolbin" "$root/apps/ios/Frameworks"
export GOBIN="$toolbin" PATH="$toolbin:$PATH" GOTOOLCHAIN=local
cd "$root"
go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20240520174638-fa72addaaa1b
go install golang.org/x/mobile/cmd/gobind@v0.0.0-20240520174638-fa72addaaa1b
go test ./...
# iOS device and simulator slices. No signing credential in the repository.
gomobile bind -target=ios,iossimulator -iosversion=16.0 -o apps/ios/Frameworks/Mobile.xcframework ./pkg/mobile
cd apps/ios
xcodegen generate --spec project.yml
case "${1:-compile}" in
 compile)
  xcodebuild -project NetworkEX.xcodeproj -scheme NetworkEX -configuration Debug -destination 'generic/platform=iOS' -derivedDataPath build/device CODE_SIGNING_ALLOWED=NO build
  echo "Unsigned device build only. No signed installation."
  ;;
 archive)
  : "${DEVELOPMENT_TEAM:?Set your Apple Developer team ID}"
  : "${NETWORK_EX_BUNDLE_ID:?Set the registered host bundle ID}"
  : "${NETWORK_EX_KEYCHAIN_GROUP:?Set the registered shared Keychain access group (including AppIdentifierPrefix)}"
  xcodebuild -project NetworkEX.xcodeproj -scheme NetworkEX -configuration Release -destination 'generic/platform=iOS' -archivePath "$PWD/build/NetworkEX.xcarchive" DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" NETWORK_EX_BUNDLE_ID="$NETWORK_EX_BUNDLE_ID" NETWORK_EX_KEYCHAIN_GROUP="$NETWORK_EX_KEYCHAIN_GROUP" archive
  echo "Archive created. Verify provisioning and export using your distribution configuration."
  ;;
 *) echo 'Usage: build-ios.sh [compile|archive]' >&2;exit 2;;
esac
