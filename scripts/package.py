"""Build a source distribution without credentials, local runtime or binaries."""
import hashlib
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = root / 'release'
output.mkdir(exist_ok=True)
archive = output / 'farstar-tunnel-1.0.0.tar.gz'
allowed = ['farstar', 'scripts', 'deploy', 'tests', 'README.md', 'VALIDATION.md', 'LICENSE', 'pyproject.toml', 'install.sh']
with tarfile.open(archive, 'w:gz') as tar:
    for name in allowed:
        path = root / name
        files = sorted(path.rglob('*')) if path.is_dir() else [path]
        for file in files:
            if not file.is_file() or '__pycache__' in file.parts or file.suffix == '.pyc':
                continue
            rel = file.relative_to(root)
            info = tar.gettarinfo(str(file), arcname='farstar-tunnel-1.0.0/' + rel.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mode = 0o755 if file.suffix == '.sh' else 0o644
            with file.open('rb') as content:
                tar.addfile(info, content)
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / 'SHA256SUMS').write_text(checksum + '  ' + archive.name + '\n')
print(f'{archive}\nSHA256: {checksum}')
