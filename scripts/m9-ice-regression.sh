#!/usr/bin/env bash
set -euo pipefail
# Do not loosen or replace the original M2 NAT firewall fixture.
# Repeat independent, fresh namespace runs and stop on the first failure.
[[ $# -ge 1 && $# -le 2 ]]||{ echo "Usage: $0 /path/to/bin [runs:2-5]" >&2;exit 2; }
bin="$(readlink -f "$1")";runs="${2:-3}"
[[ "$runs" =~ ^[2-5]$ && -x "$bin/network-ex-server" && -x "$bin/network-ex-agent" ]]||{ echo "Invalid run count or missing binaries" >&2;exit 2; }
here="$(cd "$(dirname "$0")"&&pwd)"
for ((i=1;i<=runs;i++));do
 echo "Strict NAT regression $i/$runs"
 "$here/m2-nat.sh" outside "$bin" || { echo "FAIL: strict NAT repetition $i/$runs; release gate remains open" >&2;exit 1; }
done
echo "PASS: $runs independent strict NAT recovery runs"
