# Network EX for iOS — implementation plan

Status: design only, not an iOS application or a signed extension. The Android file-descriptor bridge is not a supported way to access an iOS VPN interface.

## Architecture

- SwiftUI host app uses NETunnelProviderManager to install a user-approved VPN configuration. Explicit connect/disconnect, enrollment and approval status, no automatic always-on or full-tunnel policy.
- Separate NEPacketTunnelProvider target uses NEPacketTunnelFlow.readPackets and writePackets, not private utun descriptors. Call setTunnelNetworkSettings with assigned IPv4 /32 and only authorized overlay routes; wait for completion before reporting the packet tunnel started.
- Add a bounded Go packet-queue adapter implementing wireguard-go tun.Device, with generation-specific ownership, bounded queue and cancellation, instead of Android's detached file descriptor. Reuse the managed authorization loop and authenticated encrypted relay. Implement platform-specific outbound connection/route exclusion and verify management/relay reachability before adding routes. Do not pretend that returning true from a socket-protection callback is an iOS equivalent of VpnService.protect.
- Use an explicitly configured App Group for extension/host configuration exchange, Keychain access group for device secrets, and never pass private keys through providerConfiguration or logs. A separate Swift credential/storage adapter is required; the Android file layout is not a final iOS key-storage design.
- Initial mode is IPv4 peer /32 split routing and WSS relay. P2P requires a separately verified network-interface selection and socket routing approach. No default route, subnets, game broadcast/TAP, always-on, DNS override, or exit routes until independently implemented and tested.
- Xcode, a Mac, Apple signing/provisioning and Network Extension entitlement com.apple.developer.networking.networkextension with packet-tunnel-provider capability are required. Use separately configured bundle IDs and App Group IDs; do not invent a signing team or ship placeholder entitlements as production credentials.

## Native validation gates

Build Go bindings as XCFramework, compile host app and packet tunnel extension; verify signed installation; permission acceptance/rejection; enrollment, approval, authorization revocation; real peer TCP/UDP; TLS/underlay routing; background/foreground and Wi-Fi/mobile transitions; stop/cancel and route teardown; expiry when management unreachable; battery/resource use. Only claim iOS support after the real extension is built and exercised.

Apple references:
- https://developer.apple.com/documentation/NetworkExtension/NEPacketTunnelProvider
- https://developer.apple.com/documentation/NetworkExtension/routing-your-vpn-network-traffic
- https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)
