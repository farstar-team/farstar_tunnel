#!/usr/bin/env python3
"""Download only official, pinned FRP artifacts; verify before extracting."""
import hashlib
import io
import os
import platform
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "0.71.0"
SHA256 = {
    "linux_amd64": "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716",
    "linux_arm64": "f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266",
    "windows_amd64": "9e5062e3e5cf07e67144a3a4acf175ef6a2486f3605dd6cf288bae34ab39819f",
}


def download(destination: Path, target: str | None = None):
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    target = target or f"{system}_{arch}"
    if target not in SHA256:
        raise SystemExit(f"Unsupported platform: {target}")
    system = target.split('_')[0]
    extension = "zip" if system == "windows" else "tar.gz"
    name = f"frp_{VERSION}_{target}"
    url = f"https://github.com/fatedier/frp/releases/download/v{VERSION}/{name}.{extension}"
    request = urllib.request.Request(url, headers={"User-Agent": "Farstar-Tunnel/1.0"})
    with urllib.request.urlopen(request, timeout=90) as response:
        content = response.read(50 * 1024 * 1024)
    if hashlib.sha256(content).hexdigest() != SHA256[target]:
        raise SystemExit("FRP checksum mismatch; installation stopped.")
    destination.mkdir(parents=True, exist_ok=True)
    with (zipfile.ZipFile(io.BytesIO(content)) if extension == "zip" else tarfile.open(fileobj=io.BytesIO(content))) as archive:
        for binary in ("frpc", "frps"):
            filename = binary + (".exe" if system == "windows" else "")
            member = f"{name}/{filename}"
            stream = archive.open(member) if extension == "zip" else archive.extractfile(member)
            if stream is None:
                raise SystemExit("Missing engine binary")
            path = destination / filename
            temp = path.with_suffix(".new")
            with stream, temp.open("wb") as out:
                out.write(stream.read())
            temp.chmod(0o755)
            os.replace(temp, path)
    print(f"Verified FRP {VERSION}: {destination}")


if __name__ == "__main__":
    download(Path(sys.argv[1] if len(sys.argv) > 1 else "bin").resolve(), sys.argv[2] if len(sys.argv) > 2 else None)
