#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo "Run as root";exit 1; }
[[ "$#" == 1 && -f "$1" ]] || { echo "Usage: sudo install-agent.sh /path/to/network-ex-agent";exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
# Explicit installation; never auto-add a user to the privileged control group.
getent group network-ex >/dev/null || groupadd --system network-ex
if systemctl is-active --quiet network-ex-agent;then echo "Stop existing Network EX service before upgrade";exit 1;fi
install -d -o root -g root -m 0755 /usr/local/libexec/network-ex
install -d -o root -g network-ex -m 0700 /var/lib/network-ex
install -o root -g root -m 0755 "$1" /usr/local/libexec/network-ex/network-ex-agent
install -o root -g root -m 0644 "$here/network-ex-agent.service" /etc/systemd/system/network-ex-agent.service
systemctl daemon-reload
systemctl enable --now network-ex-agent
echo "Explicitly authorize a trusted local user: sudo usermod -aG network-ex USERNAME (then log out and back in)"
