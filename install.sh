#!/usr/bin/env bash
# Works from a checkout or directly through curl | sudo bash.
set -Eeuo pipefail
umask 022
REPOSITORY=farstar-team/farstar_tunnel
REF=${FARSTAR_REF:-main}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]]; then
  LOCAL_SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  if [[ -f $LOCAL_SOURCE/scripts/install.sh && -f $LOCAL_SOURCE/pyproject.toml ]]; then
    exec bash "$LOCAL_SOURCE/scripts/install.sh" "$@"
  fi
fi

[[ $(id -u) == 0 ]] || die 'Use: curl -fsSL https://raw.githubusercontent.com/farstar-team/farstar_tunnel/main/install.sh | sudo bash'
command -v curl >/dev/null || die 'Install curl first: sudo apt-get install curl'
command -v tar >/dev/null || die 'tar is required'
[[ $REF =~ ^[a-zA-Z0-9._-]+$ ]] || die 'FARSTAR_REF must be a branch, tag or commit without slashes'
WORK=$(mktemp -d /tmp/farstar-install.XXXXXXXX)
trap 'rm -rf -- "$WORK"' EXIT
printf 'Downloading Farstar Tunnel (%s)...\n' "$REF"
curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
  --connect-timeout 20 --max-time 300 --retry 3 \
  "https://codeload.github.com/$REPOSITORY/tar.gz/$REF" -o "$WORK/source.tar.gz"
mkdir "$WORK/source"
tar -xzf "$WORK/source.tar.gz" --strip-components=1 --no-same-owner -C "$WORK/source"
[[ -f $WORK/source/scripts/install.sh && -f $WORK/source/pyproject.toml ]] || die 'The downloaded source is incomplete'
bash "$WORK/source/scripts/install.sh" "$@"
