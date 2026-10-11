"""Private persistent state, input validation and local certificate authority."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import BaseModel, Field, field_validator, model_validator

FRP_VERSION = "0.71.0"
MAX_TUNNELS = 16
TLS_NAME = "farstar.internal"


def private_write(path: Path, content: str | bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content.encode() if isinstance(content, str) else content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    path.chmod(0o600)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return base64.b64encode(salt + key).decode()


def password_matches(password: str, encoded: str) -> bool:
    try:
        raw = base64.b64decode(encoded, validate=True)
        key = hashlib.scrypt(password.encode(), salt=raw[:16], n=16384, r=8, p=1)
        return hmac.compare_digest(key, raw[16:])
    except (ValueError, TypeError):
        return False


def validate_host(host: str) -> str:
    if len(host) > 253 or not host:
        raise ValueError("آدرس سرور معتبر نیست")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host):
            raise ValueError("فقط IP یا نام دامنه؛ بدون مسیر و پروتکل")
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
            raise ValueError("نام دامنه معتبر نیست")
    return host


def host_url(host: str, port: int) -> str:
    return f"https://{'[' + host + ']' if ':' in host else host}:{port}"


def port_available(port: int, kind: str = "tcp", host: str = "0.0.0.0") -> bool:
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM) as sock:
        try:
            # Never use SO_REUSEADDR: do not steal an existing listener on Windows.
            sock.bind((host, port))
            return True
        except OSError:
            return False


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Mapping(BaseModel):
    protocol: Literal["tcp", "udp"] = "tcp"
    listen_port: int = Field(ge=1024, le=65535)
    target_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    target_port: int = Field(ge=1, le=65535)
    health_check: bool = True


class TunnelInput(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    peer_id: str = Field(pattern=r"^[a-f0-9]{24}$")
    transport: Literal["auto", "tcp", "quic", "wss"] = "auto"
    control_port: int = Field(ge=1024, le=65535)
    bind_host: Literal["0.0.0.0", "127.0.0.1"] = "0.0.0.0"
    mappings: list[Mapping] = Field(min_length=1, max_length=16)
    bandwidth_mbps: int = Field(default=0, ge=0, le=10000)
    compression: bool = False
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError("نام تونل معتبر نیست")
        return value.strip()

    @model_validator(mode="after")
    def unique_ports(self):
        keys = [(m.protocol, m.listen_port) for m in self.mappings]
        if len(keys) != len(set(keys)) or self.control_port in [m.listen_port for m in self.mappings]:
            raise ValueError("پورت کنترل و پورت‌های ورودی نباید تکراری باشند")
        return self


class Store:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Production operations run on one event loop; disabling the affinity check
        # also permits lifespan-driven TestClient tests to use their loop thread.
        self.db = sqlite3.connect(root / "state.db", check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, csrf TEXT, expires REAL);
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL, kind TEXT, message TEXT);
        ''')
        self.db.commit()
        (root / "state.db").chmod(0o600)

    def get(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, json.dumps(value)))

    def audit(self, kind: str, message: str):
        with self.db:
            self.db.execute("INSERT INTO audit(at,kind,message) VALUES (?,?,?)", (time.time(), kind, message[:1000]))
            self.db.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id)-1000 FROM audit)")

    def events(self):
        return [dict(zip(("id", "at", "kind", "message"), row)) for row in
                self.db.execute("SELECT id,at,kind,message FROM audit ORDER BY id DESC LIMIT 100")]

    def close(self):
        self.db.close()


def certificates(root: Path, host: str):
    """Separate per-installation CA; peer trusts only this CA, including hostname."""
    pki = root / "pki"
    pki.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (pki / "server.crt").exists():
        return
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Farstar node CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    names = [x509.DNSName(TLS_NAME), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        names.append(x509.DNSName(host))
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_NAME)]))
              .issuer_name(subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
              .add_extension(x509.SubjectAlternativeName(names), critical=False)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
              .sign(key, hashes.SHA256()))
    fmt = serialization.Encoding.PEM
    private_write(pki / "ca.crt", ca.public_bytes(fmt))
    private_write(pki / "ca.key", key.private_bytes(fmt, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(pki / "server.crt", server.public_bytes(fmt))
    private_write(pki / "server.key", server_key.private_bytes(fmt, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def renew_certificate(root: Path, host: str):
    """Keep the CA and peer trust while replacing the expiring server leaf."""
    pki = root / "pki"
    ca = x509.load_pem_x509_certificate((pki / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((pki / "ca.key").read_bytes(), password=None)
    key = serialization.load_pem_private_key((pki / "server.key").read_bytes(), password=None)
    old = x509.load_pem_x509_certificate((pki / "server.crt").read_bytes())
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(old.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    private_write(pki / "server.crt", cert.public_bytes(serialization.Encoding.PEM))
