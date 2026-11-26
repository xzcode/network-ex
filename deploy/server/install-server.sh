#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]]||{ echo "Run as root" >&2;exit 1; }
[[ "$#" == 1 && -f "$1" ]]||{ echo "Usage: sudo install-server.sh /path/to/network-ex-server" >&2;exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
if systemctl is-active --quiet network-ex-server.service;then echo "Stop the existing service before upgrade" >&2;exit 1;fi
if ! getent passwd network-ex-server >/dev/null;then
 getent group network-ex-server >/dev/null||groupadd --system network-ex-server
 useradd --system --gid network-ex-server --home-dir /var/lib/network-ex-server --shell /usr/sbin/nologin network-ex-server
fi
# Never use a pre-existing unrelated privileged account.
[[ "$(id -u network-ex-server)" != 0 && "$(id -gn network-ex-server)" == network-ex-server ]]||{ echo "Invalid pre-existing service account" >&2;exit 1; }
install -d -o root -g root -m 0755 /usr/local/libexec/network-ex-server
install -d -o root -g network-ex-server -m 0750 /etc/network-ex-server
install -d -o network-ex-server -g network-ex-server -m 0700 /var/lib/network-ex-server
install -o root -g root -m 0755 "$1" /usr/local/libexec/network-ex-server/network-ex-server
install -o root -g root -m 0755 "$here/start-server" /usr/local/libexec/network-ex-server/start-server
install -o root -g root -m 0644 "$here/network-ex-server.service" /etc/systemd/system/network-ex-server.service
if [[ ! -e /etc/network-ex-server/server.env && ! -L /etc/network-ex-server/server.env ]];then
 install -o root -g network-ex-server -m 0640 "$here/server.env.example" /etc/network-ex-server/server.env
fi
systemctl daemon-reload
echo "Installed service files only. Prepare certificates, issuer/admin or registered relay identity, review server.env, then explicitly start."
