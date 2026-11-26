# M7 LAN game discovery (2026-11-26)

Version 0.7.0-dev-m7. The IPv4 UDP discovery core is implemented and verified on Linux. It is a controlled Layer-3 discovery overlay, not a transparent Ethernet bridge.

## Configuration
SQLite schema v5 adds discovery policy per network and a signed-device-snapshot discovery opt-in bit. Administrator GET/PUT /api/v1/networks/{id}/discovery (network owners can read; administrator writes). Example:
```json
{"rules":[{"destination":"10.88.0.255","port":19021},{"destination":"239.88.0.7","port":19022},{"destination":"255.255.255.255","port":19023}]}
```
The subnet-directed broadcast must match the network CIDR. Allowed destinations: the subnet broadcast, 255.255.255.255, and administratively scoped IPv4 multicast 239/8. At most 16 distinct address/UDP-port pairs; no unrestricted broadcast, unicast destinations, or link-local multicast groups. Empty rules disables discovery. The Web admin page edits these rules and stores no special game credentials.

Local administrator opts in with `network-ex-agent managed-run ... -game-discovery` or `network-ex-agent daemon ... -game-discovery` (default profile only). Default is off; additional daemon profiles are not automatically opted in. Only authorized peers with a fresh signed snapshot announcing opt-in are eligible. A network policy edit increments the revision and triggers client reconfiguration; clearing the policy removes discovery routes. Normal unicast does not depend on discovery. Applications may need to select the Network EX virtual adapter or bind the overlay address. The kernel routes only selected destinations to that adapter; other NICs and default routes are not bridged.

## Data plane
The TUN wrapper handles approved UDP packets up to 1200 bytes including IPv4/UDP headers, validates exact virtual source, destination and UDP length, and rejects fragments, nested encapsulations, nonmembers and unauthorized destination ports. Each eligible destination peer gets a unicast IPv4 envelope (experimental inner IP protocol 253) through the existing WireGuard tunnel. The underlying WireGuard peer key, AllowedIPs, ICE path selection and WSS relay continue to provide transport and source authentication. The receiver checks the exact outer peer address and inner source, both ends' device/service ACL, local opt-in and discovery policy, and injects only the original UDP datagram into its own TUN. Source IP/UDP port and destination are preserved; TTL is reduced to 1. Raw experimental-protocol packets cannot traverse the ordinary M7 guard, and received discovery is not recursively flooded. The guard tracks eligible UDP reply flows.
Bounded queues (256 envelopes), original outbound discovery rate 16/s, fanout 128/s, inbound aggregate 128/s and per-peer 16/s, token-bucket bursts equal to the corresponding rates. These are initial protective limits, not performance guarantees. No ARP, MAC forwarding, physical bridge, VLAN or IPv6 multicast support. Policy-approved discovery routes are checked against existing exact routes; setup fails rather than replacing an existing other-interface route. TUN teardown removes its routes. Linux only; other platforms refuse discovery configuration.
The Agent reports encapsulated/decoded/dropped counters. The Vue overview displays these actual counters if present (reset on tunnel rebuild). Counts are codec events, not guaranteed end-to-end delivery counts.

## Verification
`scripts/m7-discovery.sh` exited 0 in isolated Linux network namespaces on the existing development host. Three managed Agents were enrolled/approved, A-B ICE direct, A-C WSS relay (C physical UDP deliberately blocked). Independent real UDP socket room responders on B/C returned their overlay IPs to A:
- directed broadcast 10.88.0.255:19021: both responders;
- multicast 239.88.0.7:19022: both responders;
- limited broadcast 255.255.255.255:19023: both responders;
- unapproved port 19024: no responder.
The fixture explicitly binds the overlay interface. Actual live counters: A encapsulated 6, dropped 1; B and C decoded 3 each. Unicast TCP/UDP baseline passed. Withdrawing policy removed broadcast and multicast routes and authorized unicast remained usable. Admin rejected unicast and link-local multicast discovery rules.
`go test ./...` passed including policy CIDR/duplicate checks and codec member, ACL, spoofed source/port, fragmentation, oversize, nested frame and rate/fanout tests. Linux server and Agent build passed; Agent cross-builds Windows amd64, macOS amd64/arm64, Linux arm64 passed (not runtime validation). Vue production build and management JS syntax passed.
Reproduce from a Linux checkout with the established test prerequisites, including root, TUN, iproute2, iptables, unshare/nsenter, Python3 and openssl:
```sh
mkdir -p bin
go build -o bin/network-ex-server ./cmd/server
CGO_ENABLED=0 go build -o bin/network-ex-agent ./cmd/agent
sudo bash scripts/m7-discovery.sh outside "$(pwd)/bin"
```
No production network was modified. Test traffic stayed inside isolated namespaces. This validates a room-discovery protocol fixture using real sockets, not a named commercial game's compatibility. No actual game client installation, native GUI/runtime, public Internet multi-host test or release.

## Remaining M7
A fully transparent Layer-2 TAP/Ethernet network is a distinct future mode: separate bounded Ethernet frame protocol over authenticated transport, explicit admin opt-in, virtual MAC address ownership, ARP, unknown-unicast/broadcast policy, split-horizon/no-transit design, bounded forwarding tables, loop and storm controls, separate MTU and cross-platform driver validation. Do not expose physical LAN Ethernet by default. The current IPv4 discovery does not need a virtual MAC address and must not be marketed as full Ethernet. Actual games on Windows/macOS/Linux need compatibility tests, especially games that infer their LAN subnet from adapter masks, use unsupported multicast, arbitrary raw frames, or bind only a physical adapter. M4 native installation, M5 cross-host HA, M6 full exit/DNS/IPv6, security and production deployment gates remain open.
