"""Each tunnel owns a process. No shell, firewall, global routing or sysctl."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .core import TLS_NAME, free_port, private_write


class EngineError(Exception):
    pass


def quote(value):
    return json.dumps(str(value), ensure_ascii=False)


def render(tunnel: dict, role: str, root: Path, metrics_port: int, metrics_password: str, protocol: str, raw_port: int = 0) -> str:
    pki = root / "pki"
    lines = [f'log.to = "console"', 'log.level = "info"', 'log.disablePrintColor = true',
             'auth.method = "token"', f'auth.token = {quote(tunnel["token"])}',
             'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
             'transport.tcpMux = true', 'transport.tcpMuxKeepaliveInterval = 15',
             'transport.quic.keepalivePeriod = 5', 'transport.quic.maxIdleTimeout = 15',
             'webServer.addr = "127.0.0.1"', f'webServer.port = {metrics_port}',
             'webServer.user = "farstar"', f'webServer.password = {quote(metrics_password)}',
             'udpPacketSize = 1500']
    if role == "hub":
        ports = ', '.join('{ single = ' + str(m['listen_port']) + ' }' for m in tunnel['mappings'])
        wss = tunnel['transport'] == 'wss'
        lines += [f'bindAddr = {quote("127.0.0.1" if wss else "0.0.0.0")}', f'bindPort = {raw_port or tunnel["control_port"]}',
                  f'proxyBindAddr = {quote(tunnel["bind_host"])}',
                  # FRP cannot force its inner TLS on WSS. A TLS-only local relay
                  # terminates outer TLS; the raw websocket listener is loopback-only.
                  f'transport.tls.force = {str(not wss).lower()}', f'transport.tls.certFile = {quote((pki / "server.crt").as_posix())}',
                  f'transport.tls.keyFile = {quote((pki / "server.key").as_posix())}',
                  'transport.maxPoolCount = 2', f'allowPorts = [{ports}]',
                  f'maxPortsPerClient = {len(tunnel["mappings"])}', 'detailedErrorsToClient = false']
        if tunnel['transport'] in ('auto', 'quic'):
            lines += [f'quicBindPort = {tunnel["control_port"]}', 'transport.quic.maxIncomingStreams = 1024']
    else:
        lines += [f'serverAddr = {quote(tunnel["server_host"])}', f'serverPort = {tunnel["control_port"]}',
                  'loginFailExit = false', f'transport.protocol = {quote(protocol)}',
                  'transport.tls.enable = true', f'transport.tls.serverName = {quote(TLS_NAME)}',
                  f'transport.tls.trustedCaFile = {quote((root / "upstream-ca.crt").as_posix())}',
                  'transport.dialServerTimeout = 5', 'transport.poolCount = 1',
                  'transport.heartbeatInterval = 10', 'transport.heartbeatTimeout = 30',
                  'transport.quic.maxIncomingStreams = 1024']
        for index, mapping in enumerate(tunnel['mappings']):
            lines += ['', '[[proxies]]', f'name = "fs-{tunnel["id"]}-{index}"',
                      f'type = {quote(mapping["protocol"])}', f'localIP = {quote(mapping["target_host"])}',
                      f'localPort = {mapping["target_port"]}', f'remotePort = {mapping["listen_port"]}',
                      f'transport.useCompression = {str(tunnel["compression"]).lower()}']
            if tunnel['bandwidth_mbps']:
                # Mbps -> bytes/sec in FRP's MB unit.
                lines += [f'transport.bandwidthLimit = "{tunnel["bandwidth_mbps"] / 8:g}MB"',
                          'transport.bandwidthLimitMode = "server"']
            if mapping['protocol'] == 'tcp' and mapping['health_check']:
                lines += ['healthCheck.type = "tcp"', 'healthCheck.timeoutSeconds = 3',
                          'healthCheck.maxFailed = 3', 'healthCheck.intervalSeconds = 10']
    return '\n'.join(lines) + '\n'


@dataclass
class Running:
    tunnel: dict
    fingerprint: str
    protocol: str
    metrics_port: int
    metrics_password: str
    process: asyncio.subprocess.Process | None = None
    reader: asyncio.Task | None = None
    started: float = 0
    retry_at: float = 0
    failures: int = 0
    connected: bool = False
    raw_port: int = 0
    relay: asyncio.Server | None = None
    relay_tasks: set = field(default_factory=set)
    logs: deque = field(default_factory=lambda: deque(maxlen=100))
    metrics: dict = field(default_factory=dict)


class Manager:
    def __init__(self, root: Path, binaries: Path, role: str, audit):
        self.root, self.binaries, self.role, self.audit = root, binaries, role, audit
        self.running: dict[str, Running] = {}
        self.lock = asyncio.Lock()
        self.http = httpx.AsyncClient(timeout=1.5, trust_env=False)

    def executable(self) -> str:
        name = "frps" if self.role == "hub" else "frpc"
        return str(self.binaries / (name + (".exe" if os.name == "nt" else "")))

    def path(self, tunnel_id):
        return self.root / "engines" / f"{tunnel_id}.toml"

    @staticmethod
    def fingerprint(tunnel):
        return hashlib.sha256(json.dumps(tunnel, sort_keys=True).encode()).hexdigest()

    async def verify(self, path: Path):
        try:
            proc = await asyncio.create_subprocess_exec(self.executable(), "verify", "-c", str(path),
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except OSError as exc:
            raise EngineError("هستهٔ FRP نصب نیست؛ مسیر bin را بررسی کنید") from exc
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), 8)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise EngineError("بررسی تنظیمات هسته زمان‌بر شد")
        if proc.returncode:
            # Redact secrets before surfacing verification diagnostics.
            detail = output.decode(errors="replace")[-1200:]
            for item in self.running.values():
                detail = detail.replace(item.tunnel['token'], '[redacted]')
            raise EngineError("تنظیمات FRP تأیید نشد: " + detail)

    async def _reader(self, item: Running):
        process = item.process
        while line := await process.stdout.readline():
            text = line.decode(errors='replace').strip().replace(item.tunnel['token'], '[redacted]')
            text = text.replace(item.metrics_password, '[redacted]')
            if '[http/middleware.go:' in text:
                continue
            item.logs.append({"at": time.time(), "message": text[:1500]})

    async def _relay_connection(self, item, reader, writer):
        task = asyncio.current_task()
        if len(item.relay_tasks) >= 64:
            writer.close()
            return
        item.relay_tasks.add(task)
        upstream = None
        pipes = []
        try:
            raw_reader, upstream = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', item.raw_port), 5)
            async def pipe(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            pipes = [asyncio.create_task(pipe(reader, upstream)), asyncio.create_task(pipe(raw_reader, writer))]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for pending in pipes:
                pending.cancel()
            if pipes:
                await asyncio.gather(*pipes, return_exceptions=True)
            writer.close()
            if upstream:
                upstream.close()
            item.relay_tasks.discard(task)

    async def _start(self, item: Running):
        content = render(item.tunnel, self.role, self.root, item.metrics_port, item.metrics_password, item.protocol, item.raw_port)
        path = self.path(item.tunnel['id'])
        private_write(path, content)
        item.process = await asyncio.create_subprocess_exec(self.executable(), '-c', str(path),
                                                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        item.started = time.time()
        item.connected = False
        item.reader = asyncio.create_task(self._reader(item))
        # Wait for the private admin API, not just successful process creation.
        for _ in range(30):
            if item.process.returncode is not None:
                break
            try:
                response = await self.http.get(f'http://127.0.0.1:{item.metrics_port}/api/' + ('serverinfo' if self.role == 'hub' else 'status'),
                                               auth=('farstar', item.metrics_password))
                if response.status_code == 200:
                    if self.role == 'hub' and item.tunnel['transport'] == 'wss':
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                        ctx.load_cert_chain(self.root / 'pki/server.crt', self.root / 'pki/server.key')
                        try:
                            item.relay = await asyncio.start_server(lambda r, w: self._relay_connection(item, r, w),
                                                                    '0.0.0.0', item.tunnel['control_port'],
                                                                    ssl=ctx, ssl_handshake_timeout=10)
                        except OSError:
                            await self._stop(item)
                            raise EngineError('پورت کنترل WSS اشغال شده است')
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
        await self._stop(item)
        raise EngineError('هسته اجرا نشد؛ تداخل پورت یا گزارش تونل را بررسی کنید')

    async def _stop(self, item: Running):
        if item.relay:
            item.relay.close()
        relay_tasks = list(item.relay_tasks)
        for task in relay_tasks:
            task.cancel()
        if relay_tasks:
            await asyncio.gather(*relay_tasks, return_exceptions=True)
        if item.relay:
            await item.relay.wait_closed()
            item.relay = None
        if item.process and item.process.returncode is None:
            item.process.terminate()
            try:
                await asyncio.wait_for(item.process.wait(), 5)
            except asyncio.TimeoutError:
                item.process.kill()
                await item.process.wait()
        if item.reader:
            await item.reader
        item.process = None
        item.connected = False

    async def apply(self, tunnel: dict):
        async with self.lock:
            tid = tunnel['id']
            old = self.running.get(tid)
            if not tunnel['enabled']:
                if old:
                    await self._stop(old)
                    self.running.pop(tid)
                return
            fingerprint = self.fingerprint(tunnel)
            if old and old.fingerprint == fingerprint:
                return
            protocol = 'quic' if tunnel['transport'] == 'auto' else tunnel['transport']
            item = Running(tunnel, fingerprint, protocol, old.metrics_port if old else free_port(), secrets.token_urlsafe(24))
            if self.role == 'hub' and tunnel['transport'] == 'wss':
                item.raw_port = free_port()
            candidate = self.path(tid).with_suffix('.candidate.toml')
            private_write(candidate, render(tunnel, self.role, self.root, item.metrics_port, item.metrics_password, protocol, item.raw_port))
            try:
                await self.verify(candidate)
            finally:
                candidate.unlink(missing_ok=True)
            if old:
                await self._stop(old)
            try:
                await self._start(item)
            except (EngineError, OSError):
                if old:
                    await self._start(old)
                raise
            self.running[tid] = item

    async def remove(self, tid):
        async with self.lock:
            if item := self.running.pop(tid, None):
                await self._stop(item)
            self.path(tid).unlink(missing_ok=True)

    async def reconcile(self, tunnels: list[dict]):
        ids = {t['id'] for t in tunnels}
        for tid in list(self.running):
            if tid not in ids:
                await self.remove(tid)
        for tunnel in tunnels:
            await self.apply(tunnel)

    async def monitor(self):
        async with self.lock:
            for item in self.running.values():
                now = time.time()
                if not item.process or item.process.returncode is not None:
                    if now >= item.retry_at:
                        item.failures += 1
                        item.retry_at = now + min(60, 2 ** min(item.failures, 6))
                        try:
                            await self._stop(item)
                            await self._start(item)
                            self.audit('engine', f'اتصال مجدد تونل {item.tunnel["name"]}')
                        except (OSError, EngineError):
                            pass
                    continue
                try:
                    url = f'http://127.0.0.1:{item.metrics_port}/api/'
                    response = await self.http.get(url + ('serverinfo' if self.role == 'hub' else 'status'),
                                                   auth=('farstar', item.metrics_password))
                    response.raise_for_status()
                    data = response.json()
                    if self.role == 'hub':
                        item.metrics = {'traffic_in': data.get('totalTrafficIn', 0), 'traffic_out': data.get('totalTrafficOut', 0),
                                        'connections': data.get('curConns', 0)}
                        item.connected = data.get('clientCounts', 0) > 0
                    else:
                        proxies = data.get('tcp', []) + data.get('udp', [])
                        item.connected = bool(proxies) and all(p.get('status') == 'running' for p in proxies)
                        item.metrics = {'proxies': [{'name': p.get('name'), 'status': p.get('status'), 'error': p.get('err', '')} for p in proxies]}
                    if item.connected:
                        item.failures = 0
                except (httpx.HTTPError, ValueError, TypeError):
                    item.connected = False
                if self.role == 'connector' and item.tunnel['transport'] == 'auto' and item.protocol == 'quic' and not item.connected and now - item.started > 20:
                    await self._stop(item)
                    item.protocol = 'tcp'
                    self.audit('fallback', f'تونل {item.tunnel["name"]}: تغییر خودکار QUIC به TCP/TLS')
                    try:
                        await self._start(item)
                    except (OSError, EngineError):
                        item.retry_at = now + 5

    def status(self):
        return {tid: {'state': ('online' if item.connected else 'connecting') if item.process and item.process.returncode is None else 'error',
                      'transport': item.protocol, 'uptime': round(time.time() - item.started), **item.metrics}
                for tid, item in self.running.items()}

    async def close(self):
        for tid in list(self.running):
            await self.remove(tid)
        await self.http.aclose()
