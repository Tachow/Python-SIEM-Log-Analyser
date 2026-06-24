"""
detectors.py — Threat detection rules for SIEM Log Analyser.

Each detector returns a list of Alert objects.
Thresholds are configurable — tune them in config.py.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Sequence

from parsers import ApacheLogEntry, SSHLogEntry


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------

SEVERITY_COLOURS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#3498db",
    "INFO":     "#95a5a6",
}


@dataclass
class Alert:
    timestamp: datetime
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str          # e.g. "Brute Force", "SQLi Attempt"
    source_ip: str
    description: str
    evidence: list[str] = field(default_factory=list)

    @property
    def colour(self) -> str:
        return SEVERITY_COLOURS.get(self.severity, "#95a5a6")


# ---------------------------------------------------------------------------
# Apache detectors
# ---------------------------------------------------------------------------

SUSPICIOUS_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "curl", "wget", "scrapy",
]

SENSITIVE_PATHS = [
    "/.env", "/wp-admin", "/phpmyadmin", "/admin",
    "/.git", "/etc/passwd", "/config", "/.htaccess",
]

SQLI_PATTERNS = ["' OR ", "1=1", "UNION SELECT", "--", "DROP TABLE", "xp_cmdshell"]
XSS_PATTERNS  = ["<script", "javascript:", "onerror=", "onload=", "alert("]


def detect_brute_force_http(
    entries: Sequence[ApacheLogEntry],
    threshold: int = 5,
    window_seconds: int = 10,
) -> list[Alert]:
    """Detect rapid 401/403 bursts from a single IP."""
    alerts = []
    by_ip: dict[str, list[ApacheLogEntry]] = defaultdict(list)

    for e in entries:
        if e.status in (401, 403):
            by_ip[e.ip].append(e)

    for ip, evts in by_ip.items():
        evts.sort(key=lambda x: x.timestamp)
        window = []
        for evt in evts:
            window = [e for e in window if (evt.timestamp - e.timestamp).total_seconds() <= window_seconds]
            window.append(evt)
            if len(window) >= threshold:
                alerts.append(Alert(
                    timestamp=evt.timestamp,
                    severity="HIGH",
                    category="Brute Force (HTTP)",
                    source_ip=ip,
                    description=f"{len(window)} failed auth attempts in {window_seconds}s",
                    evidence=[e.raw for e in window[-3:]],
                ))
                window = []  # reset after alert to avoid duplicates

    return alerts


def detect_suspicious_ua(entries: Sequence[ApacheLogEntry]) -> list[Alert]:
    alerts = []
    seen = set()
    for e in entries:
        ua_lower = e.user_agent.lower()
        for ua in SUSPICIOUS_UAS:
            key = (e.ip, ua)
            if ua in ua_lower and key not in seen:
                seen.add(key)
                alerts.append(Alert(
                    timestamp=e.timestamp,
                    severity="MEDIUM",
                    category="Suspicious User-Agent",
                    source_ip=e.ip,
                    description=f"Known scanner/tool UA detected: '{ua}'",
                    evidence=[e.raw],
                ))
    return alerts


def detect_path_traversal_and_recon(entries: Sequence[ApacheLogEntry]) -> list[Alert]:
    alerts = []
    for e in entries:
        for path in SENSITIVE_PATHS:
            if e.path.lower().startswith(path.lower()):
                alerts.append(Alert(
                    timestamp=e.timestamp,
                    severity="HIGH",
                    category="Sensitive Path Access",
                    source_ip=e.ip,
                    description=f"Attempt to access sensitive path: {e.path}",
                    evidence=[e.raw],
                ))
    return alerts


def detect_injection_attempts(entries: Sequence[ApacheLogEntry]) -> list[Alert]:
    alerts = []
    for e in entries:
        for pattern in SQLI_PATTERNS:
            if pattern.upper() in e.path.upper():
                alerts.append(Alert(
                    timestamp=e.timestamp,
                    severity="CRITICAL",
                    category="SQL Injection Attempt",
                    source_ip=e.ip,
                    description=f"SQLi pattern '{pattern}' in request path",
                    evidence=[e.raw],
                ))
        for pattern in XSS_PATTERNS:
            if pattern.lower() in e.path.lower():
                alerts.append(Alert(
                    timestamp=e.timestamp,
                    severity="HIGH",
                    category="XSS Attempt",
                    source_ip=e.ip,
                    description=f"XSS pattern '{pattern}' in request path",
                    evidence=[e.raw],
                ))
    return alerts


def run_apache_detectors(entries: Sequence[ApacheLogEntry]) -> list[Alert]:
    alerts = []
    alerts += detect_brute_force_http(entries)
    alerts += detect_suspicious_ua(entries)
    alerts += detect_path_traversal_and_recon(entries)
    alerts += detect_injection_attempts(entries)
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


# ---------------------------------------------------------------------------
# SSH detectors
# ---------------------------------------------------------------------------

def detect_ssh_brute_force(
    entries: Sequence[SSHLogEntry],
    threshold: int = 5,
    window_seconds: int = 30,
) -> list[Alert]:
    alerts = []
    by_ip: dict[str, list[SSHLogEntry]] = defaultdict(list)

    for e in entries:
        if e.event_type == "failed" and e.src_ip:
            by_ip[e.src_ip].append(e)

    for ip, evts in by_ip.items():
        evts.sort(key=lambda x: x.timestamp)
        window = []
        for evt in evts:
            window = [e for e in window if (evt.timestamp - e.timestamp).total_seconds() <= window_seconds]
            window.append(evt)
            if len(window) >= threshold:
                usernames = list({e.username for e in window if e.username})
                alerts.append(Alert(
                    timestamp=evt.timestamp,
                    severity="CRITICAL",
                    category="SSH Brute Force",
                    source_ip=ip,
                    description=f"{len(window)} failed SSH logins in {window_seconds}s (targets: {', '.join(usernames)})",
                    evidence=[e.raw for e in window[-3:]],
                ))
                window = []

    return alerts


def detect_successful_after_failures(entries: Sequence[SSHLogEntry]) -> list[Alert]:
    """Flag IPs that failed repeatedly and then succeeded — likely successful brute force."""
    alerts = []
    by_ip: dict[str, list[SSHLogEntry]] = defaultdict(list)
    for e in entries:
        if e.src_ip:
            by_ip[e.src_ip].append(e)

    for ip, evts in by_ip.items():
        evts.sort(key=lambda x: x.timestamp)
        failed_count = 0
        for evt in evts:
            if evt.event_type == "failed":
                failed_count += 1
            elif evt.event_type == "accepted" and failed_count >= 3:
                alerts.append(Alert(
                    timestamp=evt.timestamp,
                    severity="CRITICAL",
                    category="Successful Login After Failures",
                    source_ip=ip,
                    description=f"Login succeeded for '{evt.username}' after {failed_count} failures — possible credential compromise",
                    evidence=[evt.raw],
                ))
                failed_count = 0

    return alerts


def detect_invalid_user_enum(
    entries: Sequence[SSHLogEntry],
    threshold: int = 3,
) -> list[Alert]:
    """Detect username enumeration via invalid user attempts."""
    alerts = []
    by_ip: dict[str, set] = defaultdict(set)

    for e in entries:
        if e.event_type == "invalid_user" and e.src_ip and e.username:
            by_ip[e.src_ip].add(e.username)

    for ip, usernames in by_ip.items():
        if len(usernames) >= threshold:
            last_event = max((e for e in entries if e.src_ip == ip), key=lambda x: x.timestamp)
            alerts.append(Alert(
                timestamp=last_event.timestamp,
                severity="HIGH",
                category="SSH User Enumeration",
                source_ip=ip,
                description=f"Tried {len(usernames)} invalid usernames: {', '.join(sorted(usernames))}",
                evidence=[],
            ))

    return alerts


def run_ssh_detectors(entries: Sequence[SSHLogEntry]) -> list[Alert]:
    alerts = []
    alerts += detect_ssh_brute_force(entries)
    alerts += detect_successful_after_failures(entries)
    alerts += detect_invalid_user_enum(entries)
    alerts.sort(key=lambda a: a.timestamp)
    return alerts

