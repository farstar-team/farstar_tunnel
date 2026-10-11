#!/usr/bin/env bash
# Offline test: execute the actual curl-pipe entry point against a source fixture.
set -Eeuo pipefail
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_DIR=$(mktemp -d /tmp/farstar-bootstrap-test.XXXXXXXX)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/fixture/project/scripts" "$TEST_DIR/mock-bin"
cp -- "$SOURCE/install.sh" "$TEST_DIR/bootstrap.sh"
printf '[project]\nname = "bootstrap-fixture"\n' > "$TEST_DIR/fixture/project/pyproject.toml"
cat > "$TEST_DIR/fixture/project/scripts/install.sh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $* == '--role hub --port 18443' ]]
printf 'Bootstrap reached installer with correct arguments.\n'
SH
tar -czf "$TEST_DIR/fixture.tar.gz" -C "$TEST_DIR/fixture" project
cat > "$TEST_DIR/mock-bin/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $* == *'https://codeload.github.com/farstar-team/farstar_tunnel/tar.gz/main'* ]]
cp -- "$FARSTAR_TEST_ARCHIVE" "${@: -1}"
SH
# Simulate root only for this downloader test; no system installer is executed.
printf '#!/usr/bin/env bash\nprintf "0\\n"\n' > "$TEST_DIR/mock-bin/id"
chmod +x "$TEST_DIR/mock-bin/curl" "$TEST_DIR/mock-bin/id"
export FARSTAR_TEST_ARCHIVE="$TEST_DIR/fixture.tar.gz"
export PATH="$TEST_DIR/mock-bin:$PATH"
cat "$TEST_DIR/bootstrap.sh" | bash -s -- --role hub --port 18443
printf 'Offline one-command bootstrap test passed.\n'
