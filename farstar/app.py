from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import ssl
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import httpx
import psutil
from cryptography import x509
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from . import __version__
from .core import (FRP_VERSION, MAX_TUNNELS, Store, TunnelInput, digest, host_url,
                   password_hash, password_matches, port_available, private_write, validate_host)
from .engine import EngineError, Manager


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=1, max_length=128)


class Setup(Credentials):
    bootstrap_token: str = Field(max_length=256)


class InviteInput(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class PairInput(BaseModel):
    invitation: str = Field(min_length=10, max_length=16000)


class Enrollment(BaseModel):
    code: str = Field(min_length=20, max_length=128)
    node_id: str = Field(pattern=r'^[a-f0-9]{24}$')
    name: str = Field(min_length=1, max_length=64)


class Report(BaseModel):
    statuses: dict = Field(default_factory=dict, max_length=16)


class PasswordChange(BaseModel):
    current: str = Field(max_length=128)
    password: str = Field(min_length=12, max_length=128)


def create_app(root: Path, binaries: Path, secure=True, sync_interval=3):
    store = Store(root)
    config = store.get('config')
    if not config:
        raise RuntimeError('Run farstar init first')
    manager = Manager(root, binaries, config['role'], store.audit)
    mutation = asyncio.Lock()
    histories = deque(maxlen=60)
    failures: dict[str, list[float]] = {}
    sync = {'state': 'unpaired', 'last_ok': 0, 'error': ''}
    stopping = asyncio.Event()
    started = time.time()
    upstream_http = None

    async def upstream_client():
        nonlocal upstream_http
        if upstream_http is None:
            ctx = ssl.create_default_context(cafile=str(root / 'upstream-ca.crt'))
            upstream_http = httpx.AsyncClient(verify=ctx, timeout=8, trust_env=False)
        return upstream_http

    async def sync_peer():
        upstream = store.get('upstream')
        if not upstream:
            return
        try:
            client = await upstream_client()
            headers = {'Authorization': 'Bearer ' + upstream['token']}
            response = await client.get(upstream['url'] + '/api/agent/desired', headers=headers)
            if response.status_code == 401:
                await manager.reconcile([])
                store.put('received', [])
                sync.update(state='revoked', error='دسترسی این سرور لغو شده است')
                return
            response.raise_for_status()
            desired = response.json()['tunnels']
            # Validate authenticated remote state before handing anything to a process.
            if len(desired) > MAX_TUNNELS:
                raise ValueError('Too many tunnels')
            for tunnel in desired:
                TunnelInput.model_validate(tunnel)
                if not isinstance(tunnel.get('id'), str) or len(tunnel['id']) != 24 or any(c not in 'abcdef0123456789' for c in tunnel['id']):
                    raise ValueError('Invalid tunnel identifier')
                validate_host(tunnel['server_host'])
                if not isinstance(tunnel['token'], str) or len(tunnel['token']) > 256:
                    raise ValueError('Invalid engine token')
            await manager.reconcile(desired)
            store.put('received', desired)
            report = await client.post(upstream['url'] + '/api/agent/report', headers=headers, json={'statuses': manager.status()})
            report.raise_for_status()
            sync.update(state='online', last_ok=time.time(), error='')
        except (httpx.HTTPError, OSError, ValueError, KeyError, EngineError) as exc:
            # An API outage must not stop established data-plane tunnels.
            sync.update(state='offline', error='ارتباط مدیریتی برقرار نیست؛ تونل‌های موجود حفظ می‌شوند')

    async def background():
        last_recovery = 0
        while not stopping.is_set():
            try:
                if config['role'] == 'connector':
                    async with mutation:
                        await sync_peer()
                elif time.time() - last_recovery >= 20:
                    last_recovery = time.time()
                    async with mutation:
                        for tunnel in store.get('tunnels', []):
                            if tunnel['enabled'] and tunnel['id'] not in manager.running:
                                try:
                                    check_ports(tunnel, check_existing=True)
                                    await manager.apply(tunnel)
                                    store.audit('engine', f'بازیابی تونل {tunnel["name"]}')
                                except (HTTPException, EngineError, OSError):
                                    pass
                await manager.monitor()
                status = manager.status()
                histories.append({'at': time.time(),
                                  'traffic_in': sum(x.get('traffic_in', 0) for x in status.values()),
                                  'traffic_out': sum(x.get('traffic_out', 0) for x in status.values()),
                                  'connections': sum(x.get('connections', 0) for x in status.values())})
            except Exception:
                store.audit('error', 'خطا در پایش؛ تلاش مجدد در دور بعد')
            try:
                await asyncio.wait_for(stopping.wait(), sync_interval)
            except asyncio.TimeoutError:
                pass

    @asynccontextmanager
    async def lifespan(app):
        if config['role'] == 'hub':
            for tunnel in store.get('tunnels', []):
                try:
                    check_ports(tunnel, check_existing=True)
                    await manager.apply(tunnel)
                except (HTTPException, EngineError, OSError):
                    store.audit('error', f'تونل {tunnel["name"]} اجرا نشد؛ پورت‌ها و هسته را بررسی کنید')
        elif store.get('received') and store.get('upstream'):
            try:
                await manager.reconcile(store.get('received'))
            except (OSError, EngineError):
                store.audit('error', 'بازیابی هستهٔ مقصد ناموفق بود')
        task = asyncio.create_task(background())
        yield
        stopping.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await manager.close()
        if upstream_http:
            await upstream_http.aclose()
        store.close()

    app = FastAPI(title='Farstar Tunnel', version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.manager = store, manager

    @app.middleware('http')
    async def security(request, call_next):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            content_length = request.headers.get('content-length')
            if content_length and (not content_length.isdigit() or int(content_length) > 65536):
                return JSONResponse({'detail': 'درخواست بیش از حد بزرگ است'}, 413)
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > 65536:
                    return JSONResponse({'detail': 'درخواست بیش از حد بزرگ است'}, 413)
                chunks.append(chunk)
            request._body = b''.join(chunks)
            origin = request.headers.get('origin')
            if origin and origin != str(request.base_url).rstrip('/'):
                return JSONResponse({'detail': 'مبدأ درخواست معتبر نیست'}, 403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        if secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.exception_handler(EngineError)
    async def engine_error(request, exc):
        return JSONResponse({'detail': str(exc)}, status_code=409)

    async def admin(request: Request):
        token = request.cookies.get('farstar_session', '')
        session = store.db.execute('SELECT csrf,expires FROM sessions WHERE token=?', (digest(token),)).fetchone()
        if not session or session[1] < time.time():
            raise HTTPException(401, 'وارد حساب شوید')
        if request.method not in ('GET', 'HEAD'):
            csrf = request.headers.get('x-farstar-csrf', '')
            if not hmac.compare_digest(csrf, session[0]):
                raise HTTPException(403, 'توکن امنیتی معتبر نیست؛ صفحه را دوباره باز کنید')
        return session[0]

    def hub():
        if config['role'] != 'hub':
            raise HTTPException(409, 'این عملیات روی سرور ورودی انجام می‌شود')

    async def agent(request: Request):
        hub()
        auth = request.headers.get('authorization', '')
        token_hash = digest(auth.removeprefix('Bearer ')) if auth.startswith('Bearer ') else ''
        for peer in store.get('peers', []):
            if hmac.compare_digest(token_hash, peer['token_hash']):
                return peer
        raise HTTPException(401, 'دسترسی سرور معتبر نیست')

    def limited(request, category='login'):
        ip = request.client.host if request.client else 'unknown'
        key = category + ':' + ip
        now = time.time()
        if len(failures) > 2000:
            for old in list(failures):
                if not failures[old] or failures[old][-1] < now - 600:
                    del failures[old]
        attempts = [t for t in failures.get(key, []) if t > now - 600]
        if len(attempts) >= 10:
            raise HTTPException(429, 'تلاش‌های زیاد؛ ده دقیقه بعد دوباره امتحان کنید')
        failures[key] = attempts + [now]
        return key

    def check_ports(tunnel, check_existing=False):
        if not tunnel['enabled']:
            return
        tid = tunnel['id']
        ports = {('tcp', tunnel['control_port'], '0.0.0.0')}
        if tunnel['transport'] in ('auto', 'quic'):
            ports.add(('udp', tunnel['control_port'], '0.0.0.0'))
        ports.update((m['protocol'], m['listen_port'], tunnel['bind_host']) for m in tunnel['mappings'])
        other = []
        for t in store.get('tunnels', []):
            if t['id'] != tid:
                other.append(t['control_port'])
                other.extend(m['listen_port'] for m in t['mappings'])
        old = manager.running.get(tid)
        owned = set()
        if old and old.process and old.process.returncode is None and not check_existing:
            owned.add(('tcp', old.tunnel['control_port'], '0.0.0.0'))
            if old.tunnel['transport'] in ('auto', 'quic'):
                owned.add(('udp', old.tunnel['control_port'], '0.0.0.0'))
            owned.update((m['protocol'], m['listen_port'], old.tunnel['bind_host']) for m in old.tunnel['mappings'])
        for protocol, port, host in ports:
            if port == config['panel_port'] or port in other:
                raise HTTPException(409, f'پورت {port} برای پنل یا تونل دیگری رزرو شده است')
            if (protocol, port, host) not in owned and not port_available(port, protocol, host):
                raise HTTPException(409, f'پورت {port}/{protocol} در اختیار سرویس دیگری است؛ پورت متفاوتی انتخاب کنید')

    @app.get('/api/bootstrap')
    async def bootstrap():
        return {'initialized': bool(store.get('admin')), 'role': config['role'], 'name': config['name'], 'version': __version__}

    @app.post('/api/setup')
    async def setup(body: Setup, request: Request):
        limited(request, 'setup')
        async with mutation:
            if store.get('admin'):
                raise HTTPException(409, 'حساب مدیر قبلاً ساخته شده است')
            if not hmac.compare_digest(digest(body.bootstrap_token), store.get('bootstrap_hash', '')):
                raise HTTPException(403, 'کد راه‌اندازی معتبر نیست؛ آن را از خروجی نصب بردارید')
            if len(body.password) < 12:
                raise HTTPException(422, 'رمز عبور حداقل ۱۲ کاراکتر باشد')
            hashed = await asyncio.to_thread(password_hash, body.password)
            store.put('admin', {'username': body.username, 'password': hashed})
            store.put('bootstrap_hash', '')
            (root / 'bootstrap.token').unlink(missing_ok=True)
            store.audit('security', 'حساب مدیر ساخته شد')
        return {'ok': True}

    @app.post('/api/login')
    async def login(body: Credentials, request: Request, response: Response):
        key = limited(request)
        account = store.get('admin') or {}
        valid = await asyncio.to_thread(password_matches, body.password, account.get('password', ''))
        if not valid or not hmac.compare_digest(body.username, account.get('username', '')):
            raise HTTPException(401, 'نام کاربری یا رمز عبور اشتباه است')
        failures.pop(key, None)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        with store.db:
            store.db.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
            store.db.execute('INSERT INTO sessions VALUES (?,?,?)', (digest(token), csrf, time.time() + 28800))
        response.set_cookie('farstar_session', token, max_age=28800, httponly=True, secure=secure, samesite='strict', path='/')
        store.audit('security', 'ورود مدیر به پنل')
        return {'csrf': csrf}

    @app.get('/api/session')
    async def session(csrf=Depends(admin)):
        return {'csrf': csrf, 'username': store.get('admin')['username']}

    @app.post('/api/logout', dependencies=[Depends(admin)])
    async def logout(request: Request, response: Response):
        with store.db:
            store.db.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get('farstar_session', '')),))
        response.delete_cookie('farstar_session', path='/')
        return {'ok': True}

    @app.post('/api/password', dependencies=[Depends(admin)])
    async def change_password(body: PasswordChange, response: Response):
        account = store.get('admin')
        if not await asyncio.to_thread(password_matches, body.current, account['password']):
            raise HTTPException(403, 'رمز فعلی اشتباه است')
        account['password'] = await asyncio.to_thread(password_hash, body.password)
        store.put('admin', account)
        with store.db:
            store.db.execute('DELETE FROM sessions')
        response.delete_cookie('farstar_session', path='/')
        store.audit('security', 'رمز عبور تغییر کرد و نشست‌ها بسته شدند')
        return {'ok': True}

    @app.get('/api/overview', dependencies=[Depends(admin)])
    async def overview():
        peers = store.get('peers', [])
        peer_reports = {p['id']: p.get('report', {}) if time.time() - p.get('last_seen', 0) < 20 else {} for p in peers}
        local = manager.status()
        tunnels = store.get('tunnels', []) if config['role'] == 'hub' else store.get('received', [])
        public_tunnels = []
        for tunnel in tunnels:
            item = {k: v for k, v in tunnel.items() if k != 'token'}
            status = local.get(tunnel['id'], {'state': 'stopped' if not tunnel['enabled'] else 'error'})
            if config['role'] == 'hub':
                reported = peer_reports.get(tunnel['peer_id'], {}).get(tunnel['id'])
                if reported:
                    state = status['state'] if status['state'] in ('error', 'stopped') else reported.get('state', 'connecting')
                    if state == 'online' and status['state'] != 'online':
                        state = 'connecting'
                    status = {**status, 'state': state, 'transport': reported.get('transport', tunnel['transport'])}
                elif tunnel['enabled'] and status['state'] == 'online':
                    status = {**status, 'state': 'unverified'}
            item['status'] = status
            public_tunnels.append(item)
        memory = psutil.virtual_memory()
        process = psutil.Process()
        used = process.memory_info().rss
        for child in process.children():
            with contextlib.suppress(psutil.Error):
                used += child.memory_info().rss
        cert = x509.load_pem_x509_certificate((root / 'pki' / 'server.crt').read_bytes())
        return {'node': config, 'version': __version__, 'engine_version': FRP_VERSION,
                'tunnels': public_tunnels,
                'peers': [{k: v for k, v in p.items() if k not in ('token_hash', 'report')} | {'online': time.time() - p.get('last_seen', 0) < 20} for p in peers],
                'upstream': {k: v for k, v in (store.get('upstream') or {}).items() if k != 'token'},
                'sync': sync, 'history': list(histories),
                'system': {'cpu': psutil.cpu_percent(), 'memory_percent': memory.percent,
                           'service_memory_mb': round(used / 1024 / 1024, 1), 'uptime': round(time.time() - started),
                           'disk_percent': psutil.disk_usage(str(root)).percent,
                           'certificate_expires': cert.not_valid_after_utc.timestamp()},
                'events': store.events()[:8]}

    @app.post('/api/invitations', dependencies=[Depends(admin)])
    async def invitation(body: InviteInput):
        hub()
        async with mutation:
            invitations = [i for i in store.get('invitations', []) if i['expires'] > time.time()]
            if len(invitations) >= 16:
                raise HTTPException(409, 'حداکثر ۱۶ دعوت فعال مجاز است')
            code = secrets.token_urlsafe(32)
            expires = time.time() + 600
            invitations.append({'hash': digest(code), 'expires': expires, 'name': body.name})
            store.put('invitations', invitations)
            data = {'version': 1, 'url': host_url(config['public_host'], config['panel_port']), 'code': code,
                    'ca': (root / 'pki' / 'ca.crt').read_text(), 'expires': expires}
            bundle = 'farstar1.' + base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
            store.audit('pairing', f'کد اتصال ده‌دقیقه‌ای برای {body.name} ساخته شد')
            return {'invitation': bundle, 'expires': expires}

    @app.post('/api/agent/enroll')
    async def enroll(body: Enrollment, request: Request):
        hub()
        limited(request, 'enroll')
        async with mutation:
            invitations = store.get('invitations', [])
            match = next((i for i in invitations if i['expires'] > time.time() and hmac.compare_digest(i['hash'], digest(body.code))), None)
            if not match:
                raise HTTPException(403, 'کد اتصال منقضی یا استفاده شده است')
            peers = store.get('peers', [])
            if len(peers) >= 16 or any(p['id'] == body.node_id for p in peers):
                raise HTTPException(409, 'سرور قبلاً متصل شده یا ظرفیت پر است')
            token = secrets.token_urlsafe(48)
            peers.append({'id': body.node_id, 'name': match['name'], 'token_hash': digest(token),
                          'last_seen': time.time(), 'created': time.time(), 'address': request.client.host})
            # Invitation consumption and enrollment are a single SQLite transaction.
            with store.db:
                store.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', ('peers', json.dumps(peers)))
                store.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', ('invitations', json.dumps([i for i in invitations if i != match])))
            store.audit('pairing', f'سرور {match["name"]} متصل شد')
            return {'token': token, 'hub_name': config['name'], 'hub_host': config['public_host']}

    @app.post('/api/pair', dependencies=[Depends(admin)])
    async def pair(body: PairInput):
        nonlocal upstream_http
        if config['role'] != 'connector':
            raise HTTPException(409, 'کد اتصال را در پنل سرور مقصد وارد کنید')
        async with mutation:
            if store.get('upstream'):
                raise HTTPException(409, 'ابتدا اتصال فعلی را قطع کنید')
            try:
                if not body.invitation.startswith('farstar1.'):
                    raise ValueError()
                data = json.loads(base64.urlsafe_b64decode(body.invitation[9:]))
                parsed = urlparse(data['url'])
                if data['version'] != 1 or parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                    raise ValueError()
                validate_host(parsed.hostname)
                if data['expires'] < time.time():
                    raise HTTPException(410, 'کد اتصال منقضی شده؛ کد جدید بسازید')
                ctx = ssl.create_default_context(cadata=data['ca'])
                async with httpx.AsyncClient(verify=ctx, timeout=10, trust_env=False) as client:
                    result = await client.post(data['url'] + '/api/agent/enroll', json={'code': data['code'], 'node_id': config['id'], 'name': config['name']})
                    if result.status_code != 200:
                        raise HTTPException(result.status_code, result.json().get('detail', 'اتصال ناموفق بود'))
                    remote = result.json()
                private_write(root / 'upstream-ca.crt', data['ca'])
                store.put('upstream', {'url': data['url'], 'token': remote['token'], 'name': remote['hub_name'], 'host': remote['hub_host']})
                if upstream_http:
                    await upstream_http.aclose()
                    upstream_http = None
                store.audit('pairing', f'به سرور ورودی {remote["hub_name"]} متصل شد')
            except (ValueError, KeyError, ssl.SSLError, TypeError):
                raise HTTPException(422, 'کد اتصال معتبر نیست')
            except httpx.HTTPError:
                raise HTTPException(502, 'سرور ورودی در دسترس نیست؛ آدرس، پورت پنل و فایروال را بررسی کنید')
            await sync_peer()
        return {'ok': True}

    @app.get('/api/agent/desired')
    async def desired(peer=Depends(agent)):
        tunnels = [{**t, 'server_host': config['public_host']} for t in store.get('tunnels', []) if t['peer_id'] == peer['id']]
        return {'tunnels': tunnels}

    @app.post('/api/agent/report')
    async def report(body: Report, peer=Depends(agent)):
        owned = {t['id'] for t in store.get('tunnels', []) if t['peer_id'] == peer['id']}
        sanitized = {}
        for tid, status in body.statuses.items():
            if tid not in owned or not isinstance(status, dict):
                continue
            state = status.get('state')
            protocol = status.get('transport')
            if state not in ('online', 'connecting', 'error') or protocol not in ('tcp', 'quic', 'wss'):
                continue
            sanitized[tid] = {'state': state, 'transport': protocol}
        peers = store.get('peers', [])
        for item in peers:
            if item['id'] == peer['id']:
                item.update(last_seen=time.time(), report=sanitized)
        store.put('peers', peers)
        return {'ok': True}

    @app.delete('/api/peers/{peer_id}', dependencies=[Depends(admin)])
    async def revoke(peer_id: str):
        hub()
        async with mutation:
            peers = store.get('peers', [])
            if not any(p['id'] == peer_id for p in peers):
                raise HTTPException(404, 'سرور پیدا نشد')
            tunnels = store.get('tunnels', [])
            for t in tunnels:
                if t['peer_id'] == peer_id:
                    await manager.remove(t['id'])
            store.put('tunnels', [t for t in tunnels if t['peer_id'] != peer_id])
            store.put('peers', [p for p in peers if p['id'] != peer_id])
            store.audit('security', 'دسترسی سرور مقصد و تونل‌هایش لغو شد')
        return {'ok': True}

    @app.post('/api/unpair', dependencies=[Depends(admin)])
    async def unpair():
        nonlocal upstream_http
        if config['role'] != 'connector':
            raise HTTPException(409, 'فقط در سرور مقصد')
        async with mutation:
            await manager.reconcile([])
            store.put('upstream', None)
            store.put('received', [])
            if upstream_http:
                await upstream_http.aclose()
                upstream_http = None
            sync.update(state='unpaired', last_ok=0, error='')
            store.audit('pairing', 'اتصال محلی به سرور ورودی قطع شد؛ دسترسی را در پنل ورودی هم لغو کنید')
        return {'ok': True}

    async def save_tunnel(body: TunnelInput, tid=None):
        hub()
        async with mutation:
            tunnels = store.get('tunnels', [])
            old = next((t for t in tunnels if t['id'] == tid), None)
            if tid and not old:
                raise HTTPException(404, 'تونل پیدا نشد')
            if not old and len(tunnels) >= MAX_TUNNELS:
                raise HTTPException(409, 'حداکثر ۱۶ تونل مجاز است')
            if not any(p['id'] == body.peer_id for p in store.get('peers', [])):
                raise HTTPException(422, 'ابتدا سرور مقصد را متصل کنید')
            tunnel = body.model_dump() | {'id': tid or secrets.token_hex(12), 'token': old['token'] if old else secrets.token_urlsafe(48),
                                          'created': old['created'] if old else time.time()}
            check_ports(tunnel)
            await manager.apply(tunnel)
            store.put('tunnels', [t for t in tunnels if t['id'] != tunnel['id']] + [tunnel])
            store.audit('tunnel', f'تونل {tunnel["name"]} {"ویرایش" if old else "ساخته"} شد')
            return {'id': tunnel['id'], 'ok': True}

    @app.post('/api/tunnels', dependencies=[Depends(admin)])
    async def new_tunnel(body: TunnelInput):
        return await save_tunnel(body)

    @app.put('/api/tunnels/{tid}', dependencies=[Depends(admin)])
    async def update_tunnel(tid: str, body: TunnelInput):
        return await save_tunnel(body, tid)

    @app.delete('/api/tunnels/{tid}', dependencies=[Depends(admin)])
    async def delete_tunnel(tid: str):
        hub()
        async with mutation:
            tunnels = store.get('tunnels', [])
            if not any(t['id'] == tid for t in tunnels):
                raise HTTPException(404, 'تونل پیدا نشد')
            await manager.remove(tid)
            store.put('tunnels', [t for t in tunnels if t['id'] != tid])
            store.audit('tunnel', 'تونل حذف شد')
        return {'ok': True}

    @app.get('/api/logs', dependencies=[Depends(admin)])
    async def logs():
        return {'events': store.events(), 'engines': {tid: list(item.logs) for tid, item in manager.running.items()}}

    @app.get('/api/backup', dependencies=[Depends(admin)])
    async def backup():
        # Portable settings only. No credentials, keys, identities or sessions.
        tunnels = [{k: v for k, v in t.items() if k in TunnelInput.model_fields} for t in store.get('tunnels', [])]
        return JSONResponse({'version': 1, 'tunnels': tunnels}, headers={'Content-Disposition': 'attachment; filename=farstar-settings.json'})

    @app.get('/api/preflight', dependencies=[Depends(admin)])
    async def preflight(port: int, protocol: str = 'tcp'):
        if not 1024 <= port <= 65535 or protocol not in ('tcp', 'udp'):
            raise HTTPException(422, 'پورت یا پروتکل معتبر نیست')
        reserved = port == config['panel_port'] or any(port == t['control_port'] or any(port == m['listen_port'] for m in t['mappings']) for t in store.get('tunnels', []))
        return {'port': port, 'protocol': protocol, 'available': not reserved and port_available(port, protocol), 'reserved': reserved}

    static = Path(__file__).parent / 'static'
    app.mount('/assets', StaticFiles(directory=static), name='assets')

    @app.get('/')
    async def index():
        return FileResponse(static / 'index.html')

    return app
