#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) == 0 ]] || { printf 'Run with sudo.\n' >&2; exit 1; }
[[ $# == 1 && $1 == --remove-program ]] || { printf 'Usage: sudo bash scripts/uninstall.sh --remove-program\nData and certificates are preserved.\n' >&2; exit 1; }
systemctl stop farstar-tunnel.service 2>/dev/null || true
systemctl disable farstar-tunnel.service 2>/dev/null || true
rm -f -- /etc/systemd/system/farstar-tunnel.service
systemctl daemon-reload
# Delete only our fixed, verified path; never follow a symlink.
[[ ! -L /opt/farstar-tunnel ]] || { printf 'Refusing symlink at /opt/farstar-tunnel\n' >&2; exit 1; }
[[ $(realpath -m -- /opt/farstar-tunnel) == /opt/farstar-tunnel ]] || exit 1
rm -rf -- /opt/farstar-tunnel
printf 'Program removed. Data preserved at /var/lib/farstar-tunnel.\nDedicated system user preserved for recovery.\n'
