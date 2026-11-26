# Network EX iOS (M8c candidate)

The SwiftUI application, Objective-C NEPacketTunnelProvider, Go packet queue and Keychain bridge are implemented as source. The Go iOS package and Objective-C bindings have been generated successfully on Linux; the native Xcode build and signed iPhone installation have NOT been run.

## Build on macOS

Prerequisites: compatible Xcode/iOS SDK, Go 1.23.12, XcodeGen, and an Apple Developer account with the Packet Tunnel Provider and Keychain Sharing capabilities for actual installation. The project uses the iOS 16 deployment target.

```sh
bash scripts/build-ios.sh compile
```

This generates a static Mobile.xcframework with device and simulator slices, generates NetworkEX.xcodeproj and attempts an unsigned device compile. It does not create an installable IPA.

For a signed archive, register the host bundle ID and its .packet-tunnel extension ID, configure provisioning and the shared access group, then set the actual values:
```sh
export DEVELOPMENT_TEAM=YOUR_TEAM_ID
export NETWORK_EX_BUNDLE_ID=YOUR_REGISTERED_HOST_BUNDLE_ID
export NETWORK_EX_KEYCHAIN_GROUP=YOUR_REGISTERED_KEYCHAIN_ACCESS_GROUP
bash scripts/build-ios.sh archive
```
The group includes the actual AppIdentifierPrefix. Both targets must be signed by compatible provisioning profiles with the same configured Keychain group. The script never guesses credentials, team IDs or provisioning profiles. Verify the archive entitlements and separately export/install with your development/distribution settings. The manual iOS unsigned-build GitHub Actions workflow is optional and has not been dispatched.

## Use

Register from the app with the HTTPS management origin, device name, one-time invitation and optional private CA. The private keys are generated locally, transferred as a bounded opaque bundle into Keychain with AfterFirstUnlockThisDeviceOnly, and never placed in providerConfiguration. Host enrollment staging and extension runtime files live only in their respective protected private containers, excluded from backup. Runtime files are needed by the shared Go implementation and are not a Secure Enclave key store; they are removed on orderly stop and stale runtime state is removed on subsequent startup under a lock. Hard termination can leave protected runtime files until that cleanup.

After administrator approval, connect using the normal system VPN consent dialog. The app creates only its own NETunnelProviderManager configuration and uses a status-only provider message. The initial version is peer /32 IPv4 split routing over authenticated WSS relay. The provider uses the public NEPacketTunnelFlow API and does not obtain a private utun file descriptor. Socket binding uses the selected physical interface index with IP_BOUND_IF/IPV6_BOUND_IF, not an unconditional callback. IPv4 control/relay DNS resolution and interface selection need native validation. Physical network interface changes stop the session; reconnect manually. No always-on, Internet default route, iOS P2P, subnet/exit, DNS override, IPv6 overlay or TAP mode is claimed.

## Verification gates

Native build, Apple signing and actual iPhone runtime are still required. Test provisioning, Keychain access before/after unlock, approval and revoke, peer TCP/UDP, TLS, route overlap, underlay socket binding, Wi-Fi/cellular transitions, extension start/stop/background, lease expiry and stale packet callbacks. See [M8c implementation and actual results](../../docs/M8C_IMPLEMENTATION.md).

Apple API references:
- https://developer.apple.com/documentation/networkextension/nepackettunnelflow
- https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)
- https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
