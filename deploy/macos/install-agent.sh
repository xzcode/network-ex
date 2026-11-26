#!/bin/bash
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo "Run as root";exit 1; }
[[ "$#" == 1 && -f "$1" ]] || { echo "Usage: sudo install-agent.sh /path/to/network-ex-agent";exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
if /bin/launchctl print system/com.xzcode.networkex.agent >/dev/null 2>&1;then echo "Stop the existing service before upgrade";exit 1;fi
/usr/bin/install -d -o root -g wheel -m 0755 /usr/local/libexec/network-ex
/usr/bin/install -d -o root -g wheel -m 0700 "/Library/Application Support/Network EX"
/usr/bin/install -o root -g wheel -m 0755 "$1" /usr/local/libexec/network-ex/network-ex-agent
/usr/bin/install -o root -g wheel -m 0755 "$here/agent-launch.sh" /usr/local/libexec/network-ex/agent-launch.sh
/usr/bin/install -o root -g wheel -m 0644 "$here/com.xzcode.networkex.agent.plist" /Library/LaunchDaemons/com.xzcode.networkex.agent.plist
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.xzcode.networkex.agent.plist
echo "Local macOS admin group is authorized to control Network EX. Verify signing and platform permissions before deployment."
