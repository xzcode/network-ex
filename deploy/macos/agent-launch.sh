#!/bin/sh
set -eu
/usr/bin/install -d -o root -g admin -m 0750 /var/run/network-ex
exec /usr/local/libexec/network-ex/network-ex-agent daemon -state-root "/Library/Application Support/Network EX" -socket /var/run/network-ex/agent.sock -socket-gid 80 -interface utun
