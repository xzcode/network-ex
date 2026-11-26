#!/bin/bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || exit 1
/bin/launchctl bootout system/com.xzcode.networkex.agent
rm -f /Library/LaunchDaemons/com.xzcode.networkex.agent.plist /usr/local/libexec/network-ex/agent-launch.sh /usr/local/libexec/network-ex/network-ex-agent
echo "Private state retained. Revoke/forget the device separately."
