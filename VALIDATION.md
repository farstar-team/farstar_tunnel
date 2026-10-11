# Verification — 2026-10-11

- The original 28 automated tests passed against FRP 0.71.0, Python 3.14 on Windows.
- All 12 additional CLI tests passed for installation credentials, immediate sign-in, password hashing, session revocation, validation, port conflicts and changing a paired ingress panel port without losing tunnel state.
- The complete 40-test suite passed after the installation and configuration changes (66.66 seconds).
- Ubuntu Bash syntax checks and the offline `curl | bash` bootstrap test passed for the new one-command entry point.
- After the final status-display changes, all 19 relevant authentication, pairing and two-panel integration tests passed again.
- Native FRP Linux amd64 was downloaded from the official release and its pinned SHA-256 verified. Actual TCP-over-TLS, TCP-over-QUIC and UDP-over-TLS round trips passed in Ubuntu under WSL, using isolated test processes.
- `frpc verify` and `frps verify` passed for TCP, QUIC, automatic mode and WSS configurations.
- JavaScript syntax and Ubuntu Bash syntax checks passed.
- The service file's systemd directives were verified in Ubuntu with an executable placeholder because `/opt/farstar-tunnel` is not installed on the development machine.
- Browser checks covered administrator sign-in, the live dashboard, the pairing dialog and mobile/desktop layouts. No browser console errors were present at the final check.

Tests cover wrong CA rejection, consumed/expired invitations, token scoping, CSRF, login throttling, session revocation, busy-port rejection, TCP/UDP transfer, QUIC-to-TCP fallback, per-tunnel rollback, independent tunnel lifecycles and continued data transfer during a management API outage.

GitHub Actions includes Linux application tests and a complete installation into a disposable Ubuntu 24.04 runner, followed by a real HTTPS administrator login and a check that repeated installation preserves state. Its result is available on the repository's Actions page.

No production servers were supplied or accessed. The complete root-level installer has not been executed on a production Ubuntu host. No throughput benchmark, prolonged load test, or country-to-country network test is claimed. Dependencies must be reachable during installation; PyPI file-host DNS prevented an additional full Python application run inside WSL, so that application's full test suite ran on Windows while native Linux FRP received separate transfer tests.
