#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || exit 1
systemctl disable --now network-ex-agent.service
rm -f /etc/systemd/system/network-ex-agent.service /usr/local/libexec/network-ex/network-ex-agent
systemctl daemon-reload
echo "Private state /var/lib/network-ex and authorization group retained; revoke/forget the device separately."
