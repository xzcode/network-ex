# Network EX Linux development packaging

Development/testing only. This package does not grant an open-source license to the project, does not certify production security, and is not a published Release.

## Build
Run scripts/package-linux-dev.sh [output-directory] on a supported Linux amd64/arm64 development host with Go 1.23.12, GCC, Python 3, tar and sha256sum. The server links the embedded SQLite C library using CGO (requires compatible Linux libc); the Agent is built without CGO. The tarball contains only executables, candidate service scripts, documentation, linked-Go-module CycloneDX inventory, module license notices and checksums. No data directory, TLS keys, node identity, invitation, password or config secrets are copied. The inventory is not a complete multi-language production SBOM.

Verify the outer .sha256 file, extract to a trusted directory, and run sha256sum -c SHA256SUMS inside the extracted package before using. Inspect the service scripts. Never install an untrusted binary or skip integrity verification.

## Server (optional systemd installation)
Run sudo bash server-service/install-server.sh ./network-ex-server. This creates a dedicated unprivileged account, root-owned program/unit/config template and private state directory; it deliberately DOES NOT enable or start the service. Review /etc/network-ex-server/server.env. Default listener is loopback TCP 8443. No public port or firewall changes. Use a TLS-verified reverse proxy for a publicly reachable HTTPS/WSS endpoint, or choose explicit high-port listener configuration. STUN UDP needs an explicit bind and firewall configuration; do not publish blindly. 

Management/all mode: generate issuer identity using the installed binary as network-ex-server, store issuer.key mode 0600 in /var/lib/network-ex-server, retain issuer.pub separately. Initialize the administrator once using admin-bootstrap and a securely created mode 0600 password file owned by that account. Do not put passwords on command lines or in server.env. Remove the temporary password file after initialization. Supply matching TLS certificate and private key; ensure private key only readable by the service account/root. Update the example.invalid origin, choose mode, review all settings and only then run systemctl start network-ex-server. Check journalctl -u network-ex-server and TLS-verified healthz. Enable at boot explicitly if wanted. For separate relay mode, copy only issuer PUBLIC key, register the relay identity using an approved one-time invitation, and remove the invitation argument/file after successful registration. See M3/M5 documents for protocol details.

Upgrade: stop service, back up consistent SQLite database and keys, verify new archive, reinstall and explicitly start. Install refuses an active service and preserves existing server.env. Uninstall preserves data/keys/config and account. Do not reuse or delete another service's directories. 
The Agent is separate (agent-service scripts); current Linux desktop installer does not automatically grant users the privileged Agent control group. Windows/macOS GUI bundles and service installation have separate prerequisites.

## Release boundaries
Do not distribute as a production-ready VPN. Project license choice, dependency/security review, native desktop/mobile installation, long-run/public network testing and OS permissions are pending. Never publish debug signing keys or privileged credentials.
