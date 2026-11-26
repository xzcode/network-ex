# Network EX Android

Native Java Android UI and VPNService. Development build. Debug artifacts are for testing, not a production release. Uses the shared Go mobile package via gomobile AAR (no separate daemon or root). Minimum API 26; compile/target API 35; Android Gradle Plugin 8.7.3 / Gradle 8.9 / JDK 17. Android arm64 and amd64 native library targets are configured.

Build from repository root on a dedicated development machine with Go 1.23+, JDK 17, Gradle 8.9, Android SDK platform 35 and NDK 27.2.12479018:
```sh
export ANDROID_HOME=/absolute/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
bash scripts/build-android.sh
```
The script installs the pinned gomobile and gobind tools into .mobile-tools/bin, builds apps/android/app/libs/network-ex-mobile.aar, then assembles the debug APK. These generated files and signing keys are excluded from version control. Do not disable TLS verification or sign a production APK using the debug key. The script verifies APK signatures, both expected native ABIs, 16 KiB ELF LOAD alignment and ZIP alignment; actual 16 KiB device runtime, current target-SDK requirements, Play VPN disclosure and production signing remain release gates.

Usage: create a network and one-time invitation in the management Web UI. Enter HTTPS origin, device name, invitation, optional trusted private CA PEM. Ask admin to approve; tap Connect and accept Android VPN consent. Notification/foreground service continues after closing the UI. The default network uses authenticated WireGuard/WSS relay; permitted peer /32 routes. The optional experimental P2P toggle uses protected UDP ICE with WSS fallback; Android device behavior still needs verification. No system default route, Internet exit, full privacy VPN, gateway/subnet, IPv6 tunnel, TAP or game discovery. Other apps can access authorized virtual peer addresses; Network EX's own UID is excluded from VPN routing and native underlay TCP/UDP sockets must pass VpnService.protect. On loss of authorization it closes the VPN fd. Route capture conflicts fail closed. Local identity deletion does not revoke server-side authorization.

M8b adds protected ICE socket creation and signal sockets. The Linux native-fd integration test verifies TCP/UDP over both direct and relay, fallback, revocation and cleanup; it is not Android runtime validation. See docs/M8B_IMPLEMENTATION.md for actual build status. iOS plan: ../ios/README.md.

The manual-only Android debug build workflow can be run via GitHub Actions if account quota permits; it does not auto-trigger or create a Release.
