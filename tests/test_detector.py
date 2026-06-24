"""
test_detectors.py — Unit tests for parser and detection logic.
Run with: pytest tests/
"""

import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from parsers import parse_apache_line, parse_ssh_line
from detectors import (
    detect_brute_force_http,
    detect_ssh_brute_force,
    detect_successful_after_failures,
    detect_injection_attempts,
    detect_suspicious_ua,
    detect_invalid_user_enum,
)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestApacheParser:
    def test_valid_line(self):
        line = '192.168.1.1 - - [15/Jun/2025:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        entry = parse_apache_line(line)
        assert entry is not None
        assert entry.ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status == 200
        assert entry.size == 1024

    def test_invalid_line_returns_none(self):
        assert parse_apache_line("not a log line") is None

    def test_post_request(self):
        line = '10.0.0.1 - - [15/Jun/2025:09:00:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "python-requests/2.28"'
        entry = parse_apache_line(line)
        assert entry.method == "POST"
        assert entry.status == 401


class TestSSHParser:
    def test_failed_password(self):
        line = "Jun 15 08:01:01 server sshd[1234]: Failed password for root from 203.0.113.88 port 44123 ssh2"
        entry = parse_ssh_line(line, year=2025)
        assert entry is not None
        assert entry.event_type == "failed"
        assert entry.username == "root"
        assert entry.src_ip == "203.0.113.88"
        assert entry.src_port == 44123

    def test_accepted_login(self):
        line = "Jun 15 08:00:01 server sshd[1234]: Accepted password for ubuntu from 192.168.1.5 port 52341 ssh2"
        entry = parse_ssh_line(line, year=2025)
        assert entry.event_type == "accepted"
        assert entry.username == "ubuntu"

    def test_invalid_user(self):
        line = "Jun 15 09:05:00 server sshd[1260]: Invalid user testuser from 198.51.100.55 port 22001 ssh2"
        entry = parse_ssh_line(line, year=2025)
        assert entry.event_type == "invalid_user"
        assert entry.username == "testuser"


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------

def make_apache(ip, status, path="/login", ua="Mozilla/5.0", offset_seconds=0):
    from parsers import ApacheLogEntry
    return ApacheLogEntry(
        ip=ip,
        timestamp=datetime(2025, 6, 15, 8, 0, offset_seconds % 60),
        method="POST",
        path=path,
        status=status,
        size=512,
        user_agent=ua,
        raw=f'{ip} - POST {path} {status}',
    )


def make_ssh(ip, event_type, username="root", offset_seconds=0):
    from parsers import SSHLogEntry
    return SSHLogEntry(
        timestamp=datetime(2025, 6, 15, 8, 0, offset_seconds % 60),
        hostname="server",
        pid=1000 + offset_seconds,
        event_type=event_type,
        username=username,
        src_ip=ip,
        src_port=44000 + offset_seconds,
        raw=f"Jun 15 08:00:{offset_seconds:02d} server sshd[..]: {event_type} for {username} from {ip}",
    )


class TestHTTPBruteForce:
    def test_triggers_on_threshold(self):
        entries = [make_apache("10.0.0.1", 401, offset_seconds=i) for i in range(6)]
        alerts = detect_brute_force_http(entries, threshold=5, window_seconds=30)
        assert len(alerts) >= 1
        assert alerts[0].category == "Brute Force (HTTP)"
        assert alerts[0].source_ip == "10.0.0.1"

    def test_does_not_trigger_below_threshold(self):
        entries = [make_apache("10.0.0.1", 401, offset_seconds=i) for i in range(3)]
        alerts = detect_brute_force_http(entries, threshold=5, window_seconds=30)
        assert len(alerts) == 0

    def test_different_ips_isolated(self):
        entries = (
            [make_apache("10.0.0.1", 401, offset_seconds=i) for i in range(6)] +
            [make_apache("10.0.0.2", 401, offset_seconds=i) for i in range(2)]
        )
        alerts = detect_brute_force_http(entries, threshold=5, window_seconds=30)
        assert all(a.source_ip == "10.0.0.1" for a in alerts)


class TestSQLiDetection:
    def test_sqli_in_path(self):
        entries = [make_apache("1.2.3.4", 400, path="/page?id=1' OR '1'='1")]
        alerts = detect_injection_attempts(entries)
        assert len(alerts) >= 1
        assert "SQL Injection" in alerts[0].category

    def test_clean_path_no_alert(self):
        entries = [make_apache("1.2.3.4", 200, path="/about")]
        alerts = detect_injection_attempts(entries)
        assert len(alerts) == 0


class TestSSHBruteForce:
    def test_triggers_on_threshold(self):
        entries = [make_ssh("203.0.113.1", "failed", offset_seconds=i) for i in range(6)]
        alerts = detect_ssh_brute_force(entries, threshold=5, window_seconds=60)
        assert len(alerts) >= 1
        assert alerts[0].severity == "CRITICAL"

    def test_success_after_failures_flagged(self):
        entries = (
            [make_ssh("5.5.5.5", "failed", offset_seconds=i) for i in range(5)] +
            [make_ssh("5.5.5.5", "accepted", offset_seconds=5)]
        )
        alerts = detect_successful_after_failures(entries)
        assert len(alerts) >= 1
        assert "Successful Login After Failures" in alerts[0].category


class TestUserEnumeration:
    def test_detects_multiple_invalid_users(self):
        usernames = ["admin", "oracle", "postgres", "testuser"]
        entries = [make_ssh("6.6.6.6", "invalid_user", username=u, offset_seconds=i)
                   for i, u in enumerate(usernames)]
        alerts = detect_invalid_user_enum(entries, threshold=3)
        assert len(alerts) >= 1
        assert "Enumeration" in alerts[0].category

