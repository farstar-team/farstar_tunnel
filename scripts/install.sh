#!/usr/bin/env bash
# Dedicated paths and service only. Never touches firewall, sysctl or routing.
set -Eeuo pipefail
# Never trace credentials even when this script was invoked with bash -x.
set +x
umask 022
PREFIX=/opt/farstar-tunnel
DATA=/var/lib/farstar-tunnel
UNIT=/etc/systemd/system/farstar-tunnel.service
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ROLE="" HOST="" NAME="" PORT="" USERNAME="" PASSWORD_STDIN=0
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --role|--host|--name|--port|--username)
      (($# >= 2)) || die "Missing value for $1"
      case "$1" in --role) ROLE=$2;; --host) HOST=$2;; --name) NAME=$2;; --port) PORT=$2;; --username) USERNAME=$2;; esac
      shift 2;;
    --password-stdin) PASSWORD_STDIN=1; shift;;
    *) die "Unknown option: $1";;
  esac
done
[[ $(id -u) == 0 ]] || die 'Run with sudo bash scripts/install.sh'
[[ -f /etc/os-release ]] || die 'Ubuntu 22.04+ is required'
# shellcheck disable=SC1091
source /etc/os-release
[[ $ID == ubuntu || $ID == debian ]] || die 'Supported: Ubuntu 22.04+ or Debian 12+'
command -v systemctl >/dev/null || die 'systemd is required'
[[ -d /run/systemd/system ]] || die 'systemd must be running'
exec 9>/run/lock/farstar-tunnel.install.lock
flock -n 9 || die 'Another Farstar installation is running'
[[ ! -L $PREFIX && ! -L $DATA ]] || die 'Refusing a symlink at an installation path'
[[ ! -e $DATA && ! -e $UNIT ]] || die 'Previous state or service exists. It was preserved; see README for recovery.'
if [[ -e $PREFIX ]]; then
  [[ -f $PREFIX/.installing && $(stat -c %u "$PREFIX/.installing") == 0 ]] || die 'Program already exists. It was preserved; see README for updates.'
fi
if [[ -z $ROLE ]]; then
  printf '\nFarstar Tunnel\n1) سرور ورودی / Ingress\n2) سرور مقصد / Destination\n'
  read -r -p 'انتخاب ۱ یا ۲ / Choose 1 or 2: ' choice </dev/tty || die 'A terminal is required; alternatively supply --role'
  case "$choice" in 1) ROLE=hub;; 2) ROLE=connector;; *) die 'Choose 1 or 2';; esac
fi
[[ $ROLE == hub || $ROLE == connector ]] || die '--role must be hub or connector'
if [[ -z $HOST ]]; then read -r -p 'آی‌پی عمومی همین سرور / Public IP or domain: ' HOST </dev/tty || die 'Supply --host'; fi
if [[ -z $PORT ]]; then
  read -r -p 'پورت پنل وب / Web panel port [8443]: ' PORT </dev/tty || die 'Supply --port'
  PORT=${PORT:-8443}
fi
[[ $PORT =~ ^[0-9]{4,5}$ ]] && ((10#$PORT >= 1024 && 10#$PORT <= 65535)) || die 'Panel port must be 1024..65535'
PORT=$((10#$PORT))
if [[ -z $USERNAME ]]; then
  read -r -p 'نام کاربری پنل / Panel username [admin]: ' USERNAME </dev/tty || die 'Supply --username'
  USERNAME=${USERNAME:-admin}
fi
[[ $USERNAME =~ ^[a-zA-Z0-9_.-]{3,64}$ ]] || die 'Username must be 3..64 letters, numbers, dots, underscores or hyphens'
unset PASSWORD CONFIRM
if ((PASSWORD_STDIN)); then
  IFS= read -r PASSWORD || [[ -n ${PASSWORD:-} ]] || die 'Provide the password on standard input'
else
  IFS= read -r -s -p 'رمز پنل (۱۲ تا ۱۲۸ کاراکتر) / Panel password: ' PASSWORD </dev/tty || die 'A terminal is required for the password'
  printf '\n'
  IFS= read -r -s -p 'تکرار رمز / Repeat password: ' CONFIRM </dev/tty || die 'A terminal is required for confirmation'
  printf '\n'
  [[ $PASSWORD == "$CONFIRM" ]] || die 'Passwords do not match'
  unset CONFIRM
fi
[[ ${#PASSWORD} -ge 12 && ${#PASSWORD} -le 128 ]] || die 'Password must contain 12..128 characters'
NAME=${NAME:-"Farstar $ROLE"}
command -v python3 >/dev/null || die 'Install python3 (3.10+) using your package manager first'
python3 - "$HOST" "$PORT" <<'PY'
import ipaddress, re, socket, sys
if sys.version_info < (3, 10):
    sys.exit('Python 3.10+ required: use Ubuntu 22.04+, Debian 12+')
host = sys.argv[1]
try:
    ipaddress.ip_address(host)
except ValueError:
    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        sys.exit('Invalid public IP/domain; do not include https:// or a port')
    if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
        sys.exit('Invalid domain name')
with socket.socket() as sock:
    try:
        sock.bind(('0.0.0.0', int(sys.argv[2])))
    except OSError:
        sys.exit('Panel port is already occupied. Choose --port with a free port.')
PY
if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  printf 'Installing missing python3-venv only; no package upgrades.\n'
  apt-get update -qq
  apt-get install -y --no-install-recommends --no-upgrade python3-venv
fi
printf 'Preparing isolated application and verified FRP engine...\n'
install -d -m 0755 "$PREFIX" "$PREFIX/app"
touch "$PREFIX/.installing"
install -d -m 0755 "$PREFIX/app/farstar"
cp -R -- "$SOURCE/farstar/." "$PREFIX/app/farstar/"
cp -- "$SOURCE/pyproject.toml" "$PREFIX/app/"
cp -- "$SOURCE/README.md" "$SOURCE/VALIDATION.md" "$PREFIX/"
install -d -m 0755 "$PREFIX/scripts"
cp -- "$SOURCE/scripts/uninstall.sh" "$PREFIX/scripts/"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --disable-pip-version-check "$PREFIX/app"
"$PREFIX/venv/bin/python" "$SOURCE/scripts/download_engine.py" "$PREFIX/bin"
if ! id farstar-tunnel >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin farstar-tunnel
else
  [[ $(id -u farstar-tunnel) -lt 1000 ]] || die 'Existing farstar-tunnel is not a system account'
fi
install -d -o farstar-tunnel -g farstar-tunnel -m 0700 "$DATA"
printf '%s\n' "$PASSWORD" | runuser -u farstar-tunnel -- "$PREFIX/venv/bin/farstar" --data-dir "$DATA" --bin-dir "$PREFIX/bin" init --role "$ROLE" --host "$HOST" --port "$PORT" --name "$NAME" --username "$USERNAME" --password-stdin
unset PASSWORD
cp -- "$SOURCE/deploy/farstar-tunnel.service" "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable --now farstar-tunnel.service
sleep 2
systemctl is-active --quiet farstar-tunnel.service || die 'Service failed. Check: journalctl -u farstar-tunnel.service -n 50'
rm -f -- "$PREFIX/.installing"
PANEL_HOST=$HOST
[[ $HOST != *:* ]] || PANEL_HOST="[$HOST]"
printf '\nInstalled successfully.\nPanel: https://%s:%s\nUsername: %s\nUse the password you chose during installation.\n' "$PANEL_HOST" "$PORT" "$USERNAME"
printf '\nThe browser will display a certificate warning for this private CA.\nVerify this SHA-256 fingerprint before trusting it:\n'
"$PREFIX/venv/bin/python" - "$DATA/pki/server.crt" <<'PY'
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import sys
cert = x509.load_pem_x509_certificate(open(sys.argv[1], 'rb').read())
print(':'.join(f'{b:02X}' for b in cert.fingerprint(hashes.SHA256())))
PY
printf '\nOpen only the panel and chosen tunnel ports in your provider firewall.\nNo firewall, routing, SSH, nginx or sysctl configuration was changed.\nDocumentation: %s/README.md\n' "$PREFIX"
