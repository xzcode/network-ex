#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" == 0 ]]||exit 1
systemctl disable --now network-ex-server.service
rm -f /etc/systemd/system/network-ex-server.service /usr/local/libexec/network-ex-server/network-ex-server /usr/local/libexec/network-ex-server/start-server
systemctl daemon-reload
echo "Configuration, database, credentials and service account preserved. Back up and remove separately if intended."
