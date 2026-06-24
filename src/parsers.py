"""
parsers.py — Log parsing for Apache access logs and SSH auth logs.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ApacheLogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    user_agent: str
    raw: str


@dataclass
class SSHLogEntry:
    timestamp: datetime
    hostname: str
    pid: int
    event_type: str      # "accepted", "failed", "invalid_user", "other"
    username: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    raw: str


# ---------------------------------------------------------------------------
# Apache access log parser
# ---------------------------------------------------------------------------

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\d+) '
    r'"[^"]*" '
    r'"(?P<ua>[^"]*)"'
)

APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_line(line: str) -> Optional[ApacheLogEntry]:
    m = APACHE_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        return ApacheLogEntry(
            ip=m.group("ip"),
            timestamp=datetime.strptime(m.group("time"), APACHE_TIME_FMT),
            method=m.group("method"),
            path=m.group("path"),
            status=int(m.group("status")),
            size=int(m.group("size")),
            user_agent=m.group("ua"),
            raw=line.strip(),
        )
    except ValueError:
        return None


def parse_apache_log(path: str) -> list[ApacheLogEntry]:
    entries = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            entry = parse_apache_line(line)
            if entry:
                entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# SSH auth log parser
# ---------------------------------------------------------------------------

SSH_TIME_FMT = "%b %d %H:%M:%S"

SSH_PATTERNS = {
    "accepted": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    ),
    "failed": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    ),
    "invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    ),
}

SSH_HEADER = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)"
)


def parse_ssh_line(line: str, year: int = None) -> Optional[SSHLogEntry]:
    year = year or datetime.now().year
    m = SSH_HEADER.match(line.strip())
    if not m:
        return None

    time_str = f"{m.group('month')} {m.group('day').zfill(2)} {m.group('time')}"
    try:
        ts = datetime.strptime(time_str, SSH_TIME_FMT).replace(year=year)
    except ValueError:
        return None

    msg = m.group("msg")
    event_type = "other"
    username = src_ip = src_port = None

    for etype, pattern in SSH_PATTERNS.items():
        pm = pattern.search(msg)
        if pm:
            event_type = etype
            username = pm.group("user")
            src_ip = pm.group("ip")
            src_port = int(pm.group("port"))
            break

    return SSHLogEntry(
        timestamp=ts,
        hostname=m.group("host"),
        pid=int(m.group("pid")),
        event_type=event_type,
        username=username,
        src_ip=src_ip,
        src_port=src_port,
        raw=line.strip(),
    )


def parse_ssh_log(path: str, year: int = None) -> list[SSHLogEntry]:
    entries = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            entry = parse_ssh_line(line, year)
            if entry:
                entries.append(entry)
    return entries

