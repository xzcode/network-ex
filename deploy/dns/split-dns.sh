#!/usr/bin/env bash
set -euo pipefail
# Explicit, opt-in, domain-scoped resolver integration.
# Does not touch global nameservers, restart services or configure routes.
usage(){ echo "Usage: $0 {print|install|remove} {dnsmasq|macos} [port]" >&2;exit 2; }
[[ $# -ge 2 && $# -le 3 ]]||usage
action="$1";backend="$2";port="${3:-15353}"
[[ "$port" =~ ^[0-9]{1,5}$ ]]||usage
port=$((10#$port));((port>=1&&port<=65535))||usage
marker="# Managed by Network EX split DNS"
case "$backend" in
 dnsmasq)
  target=/etc/dnsmasq.d/network-ex.conf
  content="$(printf '%s\nserver=/network-ex.internal/127.0.0.1#%s\nrebind-domain-ok=/network-ex.internal/\n' "$marker" "$port")"
  ;;
 macos)
  target=/etc/resolver/network-ex.internal
  content="$(printf '%s\nnameserver 127.0.0.1\nport %s\n' "$marker" "$port")"
  ;;
 *) usage;;
esac
if [[ "$action" == print ]];then printf '%s\n' "$content";exit 0;fi
[[ "$(id -u)" == 0 ]]||{ echo "Administrator privileges required" >&2;exit 1; }
case "$backend" in
 dnsmasq) [[ "$(uname -s)" == Linux ]]&&command -v dnsmasq >/dev/null||{ echo "Requires Linux with dnsmasq; ensure its config includes /etc/dnsmasq.d" >&2;exit 1; };;
 macos) [[ "$(uname -s)" == Darwin ]]||{ echo "Requires macOS" >&2;exit 1; };;
esac
case "$action" in
 install)
  if [[ "$backend" == macos && ! -e /etc/resolver ]];then /usr/bin/install -d -o root -g wheel -m 0755 /etc/resolver;fi
  [[ -d "$(dirname "$target")" && ! -L "$(dirname "$target")" ]]||{ echo "Resolver directory missing or symlink; inspect manually" >&2;exit 1; }
  [[ ! -e "$target" && ! -L "$target" ]]||{ echo "Resolver file exists; refusing overwrite: $target" >&2;exit 1; }
  (umask 022;set -o noclobber;printf '%s\n' "$content" > "$target")
  if [[ "$backend" == dnsmasq ]];then
   if ! dnsmasq --test;then rm -f -- "$target";echo "Validation failed; new file removed" >&2;exit 1;fi
   echo "Installed $target. Verify your active dnsmasq includes this directory, then reload it explicitly."
  else echo "Installed $target. Verify with scutil --dns."
  fi
  ;;
 remove)
  [[ -f "$target" && ! -L "$target" ]]||{ echo "Owned resolver file not found: $target" >&2;exit 1; }
  [[ "$(cat "$target")" == "$content" ]]||{ echo "Resolver file differs; refusing removal. Supply original port or inspect manually." >&2;exit 1; }
  rm -- "$target"
  echo "Removed $target. If using dnsmasq, reload the active instance explicitly."
  ;;
 *) usage;;
esac
