import asyncio
import json
import secrets
import socket
import ssl
import contextlib
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn

from farstar.app import create_app
from farstar.core import certificates, free_port, private_write
from farstar.engine import EngineError, Manager, render
from conftest import initialize


def tunnel_spec(transport='tcp', target_port=None):
    ports = []
    while len(ports) < 3:
        p=free_port()
        if p not in ports:
            ports.append(p)
    return {'id': secrets.token_hex(12), 'name': 'Integration', 'peer_id': 'a'*24,
            'transport': transport, 'control_port': ports[0], 'bind_host': '127.0.0.1',
            'bandwidth_mbps': 8, 'compression': False, 'enabled': True, 'server_host': '127.0.0.1',
            'token': secrets.token_urlsafe(48),
            'mappings': [{'protocol': 'tcp', 'listen_port': ports[1], 'target_port': target_port or ports[2],
                          'target_host': '127.0.0.1', 'health_check': False}]}


def require_engine(binaries):
    if not (binaries / ('frps.exe' if __import__('os').name == 'nt' else 'frps')).exists():
        pytest.skip('Download pinned FRP with scripts/download_engine.py first')


@pytest.mark.parametrize('transport', ['tcp', 'quic', 'auto', 'wss'])
async def test_configs_verified_by_real_frp(tmp_path, binaries, transport):
    require_engine(binaries)
    certificates(tmp_path, '127.0.0.1')
    private_write(tmp_path/'upstream-ca.crt', (tmp_path/'pki/ca.crt').read_bytes())
    spec = tunnel_spec(transport)
    for role in ('hub', 'connector'):
        manager=Manager(tmp_path,binaries,role,lambda *_:None)
        path=tmp_path/f'{role}.toml'
        private_write(path,render(spec,role,tmp_path,free_port(),'metrics-secret','quic' if transport=='auto' else transport))
        try:
            await manager.verify(path)
        finally:
            await manager.close()


async def wait_connected(manager, timeout=12):
    for _ in range(int(timeout*5)):
        await manager.monitor()
        if all(item.connected for item in manager.running.values()) and manager.running:
            return
        await asyncio.sleep(.2)
    raise AssertionError(json.dumps({k:{'logs':list(v.logs),'status':manager.status()} for k,v in manager.running.items()},ensure_ascii=False))


async def echo(reader, writer):
    try:
        size = int.from_bytes(await reader.readexactly(4), 'big')
        if size > 65536:
            return
        data = await reader.readexactly(size)
        writer.write(data)
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def roundtrip(port, payload=b'farstar encrypted data'):
    reader,writer=await asyncio.open_connection('127.0.0.1',port)
    try:
        writer.write(len(payload).to_bytes(4, 'big') + payload)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(payload)),5)==payload
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.parametrize('transport',['tcp','quic','wss'])
async def test_real_encrypted_tcp_transfer_and_metrics(tmp_path,binaries,transport):
    require_engine(binaries)
    certificates(tmp_path,'127.0.0.1')
    private_write(tmp_path/'upstream-ca.crt',(tmp_path/'pki/ca.crt').read_bytes())
    service=await asyncio.start_server(echo,'127.0.0.1',0)
    spec=tunnel_spec(transport,service.sockets[0].getsockname()[1])
    hub=Manager(tmp_path/'hub',binaries,'hub',lambda *_:None)
    connector=Manager(tmp_path/'connector',binaries,'connector',lambda *_:None)
    # Managers use distinct directories but trust one hub's cert.
    for filename in ('ca.crt','server.crt','server.key'):
        private_write(hub.root/'pki'/filename,(tmp_path/'pki'/filename).read_bytes())
    private_write(connector.root/'upstream-ca.crt',(tmp_path/'pki/ca.crt').read_bytes())
    try:
        await hub.apply(spec)
        await connector.apply(spec)
        await wait_connected(connector)
        await wait_connected(hub)
        await roundtrip(spec['mappings'][0]['listen_port'],secrets.token_bytes(8192))
        # FRP accounts TCP bytes after both halves of a stream are closed.
        for _ in range(25):
            await asyncio.sleep(.2)
            await hub.monitor()
            if hub.status()[spec['id']]['traffic_in'] > 0:
                break
        assert hub.status()[spec['id']]['traffic_in'] > 0
        assert hub.status()[spec['id']]['traffic_out'] > 0
        # Candidate failure rolls back only this tunnel to its known working config.
        original=hub._start
        first=True
        async def fail_once(item):
            nonlocal first
            if first:
                first=False
                raise EngineError('simulated startup failure')
            await original(item)
        hub._start=fail_once
        with pytest.raises(EngineError):
            await hub.apply({**spec,'compression':True})
        hub._start=original
        await asyncio.sleep(1)
        await wait_connected(hub, timeout=30)
        await wait_connected(connector)
        await roundtrip(spec['mappings'][0]['listen_port'])
    finally:
        await connector.close()
        await hub.close()
        service.close()
        await service.wait_closed()


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self,transport):
        self.transport=transport
    def datagram_received(self,data,addr):
        self.transport.sendto(data,addr)


async def test_real_udp_transfer(tmp_path,binaries):
    require_engine(binaries)
    certificates(tmp_path,'127.0.0.1')
    private_write(tmp_path/'upstream-ca.crt',(tmp_path/'pki/ca.crt').read_bytes())
    loop=asyncio.get_running_loop()
    udp,_=await loop.create_datagram_endpoint(UdpEcho,local_addr=('127.0.0.1',0))
    spec=tunnel_spec('tcp',udp.get_extra_info('sockname')[1])
    spec['mappings'][0]['protocol']='udp'
    hub=Manager(tmp_path,binaries,'hub',lambda *_:None)
    connector=Manager(tmp_path,binaries,'connector',lambda *_:None)
    # Same root would overwrite the server config; use separate engine directories.
    connector.path=lambda tid:tmp_path/'client'/f'{tid}.toml'
    try:
        await hub.apply(spec)
        await connector.apply(spec)
        await wait_connected(connector)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            await loop.sock_sendto(sock,b'udp-through-tls',('127.0.0.1',spec['mappings'][0]['listen_port']))
            data,_=await asyncio.wait_for(loop.sock_recvfrom(sock,2048),5)
            assert data==b'udp-through-tls'
    finally:
        await connector.close()
        await hub.close()
        udp.close()


async def test_auto_fallback_and_certificate_rejection(tmp_path,binaries):
    require_engine(binaries)
    certificates(tmp_path,'127.0.0.1')
    private_write(tmp_path/'upstream-ca.crt',(tmp_path/'pki/ca.crt').read_bytes())
    service=await asyncio.start_server(echo,'127.0.0.1',0)
    spec=tunnel_spec('auto',service.sockets[0].getsockname()[1])
    hub=Manager(tmp_path,binaries,'hub',lambda *_:None)
    connector=Manager(tmp_path,binaries,'connector',lambda *_:None)
    connector.path=lambda tid:tmp_path/'client'/f'{tid}.toml'
    try:
        # Deliberately disable UDP on the server to exercise QUIC -> TLS fallback.
        await hub.apply({**spec,'transport':'tcp'})
        await connector.apply(spec)
        connector.running[spec['id']].started-=21
        await connector.monitor()
        assert connector.running[spec['id']].protocol=='tcp'
        await wait_connected(connector)
        await roundtrip(spec['mappings'][0]['listen_port'])
        # Wrong CA must fail closed, never bypass TLS verification.
        await connector.remove(spec['id'])
        certificates(tmp_path/'wrong-ca','127.0.0.1')
        private_write(tmp_path/'upstream-ca.crt',(tmp_path/'wrong-ca/pki/ca.crt').read_bytes())
        await connector.apply({**spec,'transport':'tcp'})
        await asyncio.sleep(1)
        await connector.monitor()
        assert not connector.running[spec['id']].connected
        wrong = ssl.create_default_context(cafile=str(tmp_path/'upstream-ca.crt'))
        with pytest.raises(ssl.SSLCertVerificationError):
            await asyncio.open_connection('127.0.0.1', spec['control_port'], ssl=wrong, server_hostname='farstar.internal')
    finally:
        await connector.close()
        await hub.close()
        service.close()
        await service.wait_closed()


@asynccontextmanager
async def live_panel(root,binaries,role):
    config=initialize(root,role)
    app=create_app(root,binaries,secure=True,sync_interval=.2)
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=config['panel_port'],
        ssl_keyfile=str(root/'pki/server.key'),ssl_certfile=str(root/'pki/server.crt'),log_level='error',access_log=False))
    task=asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:break
            await asyncio.sleep(.1)
        assert server.started
        ctx=ssl.create_default_context(cafile=str(root/'pki/ca.crt'))
        async with httpx.AsyncClient(base_url=f'https://127.0.0.1:{config["panel_port"]}',verify=ctx,timeout=15,trust_env=False) as client:
            await client.post('/api/setup',json={'bootstrap_token':'test-bootstrap-secret','username':'admin','password':'long-test-password'})
            result=await client.post('/api/login',json={'username':'admin','password':'long-test-password'})
            assert result.status_code==200
            client.headers['X-Farstar-CSRF']=result.json()['csrf']
            yield client,app,config
    finally:
        server.should_exit=True
        await task


async def test_two_panels_pair_sync_isolation_restart_and_revocation(tmp_path,binaries):
    require_engine(binaries)
    service=await asyncio.start_server(echo,'127.0.0.1',0)
    try:
        async with live_panel(tmp_path/'hub',binaries,'hub') as (hub,hubapp,hcfg), live_panel(tmp_path/'connector',binaries,'connector') as (client,capp,ccfg):
            invitation=(await hub.post('/api/invitations',json={'name':'Destination'})).json()['invitation']
            result=await client.post('/api/pair',json={'invitation':invitation})
            assert result.status_code==200,result.text
            spec=tunnel_spec('tcp',service.sockets[0].getsockname()[1])
            spec['peer_id']=ccfg['id']
            body={k:v for k,v in spec.items() if k not in ('id','token','server_host')}
            result=await hub.post('/api/tunnels',json=body)
            assert result.status_code==200,result.text
            tid=result.json()['id']
            await asyncio.sleep(1)
            await wait_connected(capp.state.manager)
            await roundtrip(spec['mappings'][0]['listen_port'])
            # A second tunnel uses its own processes, and must survive edits/deletion of first.
            second=tunnel_spec('tcp',service.sockets[0].getsockname()[1])
            second['peer_id']=ccfg['id']
            body2={k:v for k,v in second.items() if k not in ('id','token','server_host')}
            result=await hub.post('/api/tunnels',json=body2)
            assert result.status_code==200,result.text
            tid2=result.json()['id']
            await asyncio.sleep(1)
            await wait_connected(capp.state.manager)
            second_pid=hubapp.state.manager.running[tid2].process.pid
            # Reject an unrelated occupied service without closing that socket.
            occupied=socket.socket()
            try:
                occupied.bind(('0.0.0.0',0));occupied.listen()
                conflict={**body,'control_port':occupied.getsockname()[1]}
                assert (await hub.post('/api/tunnels',json=conflict)).status_code==409
                assert occupied.fileno()>=0
            finally:
                occupied.close()
            assert (await hub.put('/api/tunnels/'+tid,json={**body,'enabled':False})).status_code==200
            await asyncio.sleep(.8)
            assert tid not in capp.state.manager.running
            assert hubapp.state.manager.running[tid2].process.pid==second_pid
            await roundtrip(second['mappings'][0]['listen_port'])
            assert (await hub.put('/api/tunnels/'+tid,json=body)).status_code==200
            await asyncio.sleep(1)
            await wait_connected(capp.state.manager)
            await roundtrip(spec['mappings'][0]['listen_port'])
            assert (await hub.delete('/api/tunnels/'+tid)).status_code==200
            await asyncio.sleep(.8)
            assert tid not in capp.state.manager.running
            await roundtrip(second['mappings'][0]['listen_port'])
            # Data survives a management-only outage / invalid endpoint, while FRP is alive.
            upstream=capp.state.store.get('upstream')
            capp.state.store.put('upstream',{**upstream,'url':'https://127.0.0.1:1'})
            await asyncio.sleep(.8)
            await roundtrip(second['mappings'][0]['listen_port'])
            capp.state.store.put('upstream',upstream)
            assert (await hub.delete('/api/peers/'+ccfg['id'])).status_code==200
            for _ in range(60):
                if not capp.state.manager.running:
                    break
                await asyncio.sleep(.2)
            assert not capp.state.manager.running
            assert not hubapp.state.manager.running
        # Relaunch the hub and assert persistent config and account survived.
        from farstar.core import Store
        store=Store(tmp_path/'hub')
        assert store.get('admin')['username']=='admin'
        assert store.get('tunnels')==[]
        store.close()
    finally:
        service.close()
        await service.wait_closed()
