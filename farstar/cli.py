import argparse
import getpass
import json
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn

from .core import (Store, certificates, digest, host_url, password_hash, port_available, private_write,
                   renew_certificate, validate_host)


def validate_username(value):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,64}', value):
        raise SystemExit('Username must be 3..64 letters, numbers, dots, underscores or hyphens.')
    return value


def read_password(from_stdin=False):
    if from_stdin:
        # Bound input before hashing and never put a password in process arguments.
        value = sys.stdin.readline(130)
        password = value.removesuffix('\n').removesuffix('\r')
    else:
        password = getpass.getpass('New password (12..128 characters): ')
        if getpass.getpass('Repeat password: ') != password:
            raise SystemExit('Password confirmation mismatch.')
    if not 12 <= len(password) <= 128 or any(c in password for c in '\r\n\x00'):
        raise SystemExit('Password must contain 12..128 characters, without line breaks or NUL.')
    return password


def main():
    parser = argparse.ArgumentParser(description='Farstar Tunnel — isolated tunnel panel')
    parser.add_argument('--data-dir', default=os.getenv('FARSTAR_DATA', '/var/lib/farstar-tunnel'))
    parser.add_argument('--bin-dir', default=os.getenv('FARSTAR_BIN', '/opt/farstar-tunnel/bin'))
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--role', choices=['hub', 'connector'], required=True)
    init.add_argument('--name', default='Farstar node')
    init.add_argument('--host', required=True)
    init.add_argument('--port', type=int, default=8443)
    init.add_argument('--username', help='Create the administrator during initialization')
    init.add_argument('--password-stdin', action='store_true', help='Read one password line from standard input')
    serve = sub.add_parser('serve')
    serve.add_argument('--listen', default='0.0.0.0')
    serve.add_argument('--dev-http', action='store_true', help='HTTP on loopback only, for local development')
    sub.add_parser('reset-password')
    sub.add_parser('renew-certificate')
    configure = sub.add_parser('configure-panel', help='Change web panel port or administrator credentials')
    configure.add_argument('--port', type=int)
    configure.add_argument('--username')
    password_source = configure.add_mutually_exclusive_group()
    password_source.add_argument('--prompt-password', action='store_true')
    password_source.add_argument('--password-stdin', action='store_true')
    upstream = sub.add_parser('configure-upstream', help='Update the paired ingress panel port on a destination')
    upstream.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    root = Path(args.data_dir).resolve()
    binaries = Path(args.bin_dir).resolve()
    os.umask(0o077)
    store = Store(root)
    if args.command == 'init':
        if store.get('config'):
            raise SystemExit('Already initialized; existing state was preserved.')
        host = validate_host(args.host)
        if not 1024 <= args.port <= 65535:
            raise SystemExit('Panel port must be between 1024 and 65535.')
        if bool(args.username) != args.password_stdin:
            raise SystemExit('Use --username together with --password-stdin, or omit both for web setup.')
        account = None
        if args.username:
            username = validate_username(args.username)
            account = {'username': username, 'password': password_hash(read_password(True))}
        certificates(root, host)
        store.put('config', {'id': secrets.token_hex(12), 'name': args.name, 'role': args.role,
                             'public_host': host, 'panel_port': args.port})
        if account:
            store.put('admin', account)
            store.put('bootstrap_hash', '')
            print(f'Initialized. Administrator: {account["username"]}')
        else:
            token = secrets.token_urlsafe(32)
            store.put('bootstrap_hash', digest(token))
            private_write(root / 'bootstrap.token', token + '\n')
            print(f'Initialized. Setup code is stored in {root / "bootstrap.token"}')
    elif args.command == 'reset-password':
        account = store.get('admin')
        if not account:
            raise SystemExit('Create the administrator in the panel first.')
        password = read_password()
        account['password'] = password_hash(password)
        store.put('admin', account)
        with store.db:
            store.db.execute('DELETE FROM sessions')
        store.audit('security', 'رمز مدیر از خط فرمان بازنشانی شد')
        print('Password updated; all sessions revoked.')
    elif args.command == 'configure-panel':
        config = store.get('config')
        account = store.get('admin')
        if not config or not account:
            raise SystemExit('Initialize the panel and create an administrator first.')
        if not any((args.port is not None, args.username is not None, args.prompt_password, args.password_stdin)):
            raise SystemExit('Supply --port, --username, --prompt-password or --password-stdin.')
        if args.port is not None:
            if not 1024 <= args.port <= 65535:
                raise SystemExit('Panel port must be between 1024 and 65535.')
            if config['role'] == 'hub' and any(
                args.port == tunnel['control_port'] or any(args.port == mapping['listen_port'] for mapping in tunnel['mappings'])
                for tunnel in store.get('tunnels', [])
            ):
                raise SystemExit('This port is reserved by a tunnel; existing settings were preserved.')
            if args.port != config['panel_port'] and not port_available(args.port):
                raise SystemExit('Panel port is already occupied; existing settings were preserved.')
            config['panel_port'] = args.port
        if args.username is not None:
            account['username'] = validate_username(args.username)
        if args.prompt_password or args.password_stdin:
            account['password'] = password_hash(read_password(args.password_stdin))
        # Commit the settings and session revocation together, after every validation.
        with store.db:
            for key, value in (('config', config), ('admin', account)):
                store.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, json.dumps(value)))
            if args.username is not None or args.prompt_password or args.password_stdin:
                store.db.execute('DELETE FROM sessions')
        store.audit('settings', 'تنظیمات پنل از خط فرمان تغییر کرد')
        print(f'Panel: {host_url(config["public_host"], config["panel_port"])}')
        print(f'Administrator: {account["username"]}')
        print('Restart only farstar-tunnel.service to apply a changed web port.')
        if args.port is not None and config['role'] == 'hub' and store.get('peers', []):
            print('Paired destination servers must use configure-upstream --port with the same web port.')
    elif args.command == 'configure-upstream':
        config = store.get('config')
        upstream = store.get('upstream')
        if not config or config['role'] != 'connector' or not upstream:
            raise SystemExit('This command requires a paired destination server.')
        if not 1024 <= args.port <= 65535:
            raise SystemExit('Ingress panel port must be between 1024 and 65535.')
        host = urlsplit(upstream['url']).hostname
        upstream['url'] = host_url(validate_host(host), args.port)
        store.put('upstream', upstream)
        store.audit('settings', 'پورت پنل ورودی برای همگام‌سازی تغییر کرد')
        print(f'Ingress panel: {upstream["url"]}. Synchronization will use this port on its next attempt.')
    elif args.command == 'renew-certificate':
        renew_certificate(root, store.get('config')['public_host'])
        print('Certificate renewed. Restart only farstar-tunnel.service to load it.')
    else:
        config = store.get('config')
        if not config:
            raise SystemExit('Run init first.')
        if args.dev_http and args.listen not in ('127.0.0.1', '::1'):
            raise SystemExit('--dev-http is restricted to loopback.')
        store.close()
        from .app import create_app
        app = create_app(root, binaries, secure=not args.dev_http)
        tls = {} if args.dev_http else {'ssl_keyfile': str(root / 'pki/server.key'), 'ssl_certfile': str(root / 'pki/server.crt')}
        uvicorn.run(app, host=args.listen, port=config['panel_port'], proxy_headers=False,
                    access_log=False, limit_concurrency=64, timeout_keep_alive=5, **tls)
        return
    store.close()


if __name__ == '__main__':
    main()
