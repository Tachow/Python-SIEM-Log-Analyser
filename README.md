# 🛡 Python SIEM Log Analyser

![CI](https://github.com/Tachow/siem-log-analyser/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

A lightweight, **zero-dependency** Security Information and Event Management (SIEM) log analyser built in Python. Parses real-world Apache and SSH logs, applies a rule-based threat detection engine, and outputs a self-contained dark-mode HTML dashboard — no ELK stack required.

Built as part of a cybersecurity portfolio to demonstrate practical SOC/blue-team skills: log parsing, threat detection logic, and security reporting.

---

## 📸 Dashboard Preview

> *Dark-mode HTML report with severity cards, doughnut chart, category bar chart, top threat IPs, and full alert table with raw log evidence.*

```
┌──────────────────────────────────────────────────────────────┐
│  🛡 SIEM Log Analysis Report           Generated: 2025-06-15 │
├──────────────┬──────────────┬──────────────┬─────────────────┤
│  CRITICAL: 3 │    HIGH: 5   │  MEDIUM: 2   │  TOTAL: 10      │
├──────────────┴──────────────┴──────────────┴─────────────────┤
│  [Severity Doughnut]          [Category Bar Chart]           │
├──────────────────────────────────────────────────────────────┤
│  TIME     SEVERITY   CATEGORY                  SOURCE IP     │
│  08:01:10 CRITICAL   Successful Login After…   203.0.113.88  │
│  08:01:06 CRITICAL   SSH Brute Force           203.0.113.88  │
│  08:15:01 CRITICAL   SQL Injection Attempt      203.0.113.47  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🎯 Features

| Feature | Detail |
|---|---|
| **Log Parsers** | Apache Combined Log Format, Linux SSH `auth.log` |
| **Brute Force Detection** | HTTP 401/403 burst detection with sliding time windows |
| **SSH Attack Detection** | Brute force, successful-login-after-failures, user enumeration |
| **Injection Detection** | SQLi and XSS pattern matching in request paths |
| **Suspicious UA Detection** | Flags known scanner tools (sqlmap, nikto, masscan, etc.) |
| **Sensitive Path Detection** | Alerts on access to `.env`, `/admin`, `/phpmyadmin`, etc. |
| **HTML Dashboard** | Self-contained dark-mode report with Chart.js visualisations |
| **Configurable Thresholds** | Tune detection sensitivity without touching core logic |
| **CI/CD** | GitHub Actions runs pytest on every push |

---

## 🗂 Project Structure

```
siem-log-analyser/
├── main.py                     # CLI entry point
├── src/
│   ├── parsers.py              # Log format parsers (Apache, SSH)
│   ├── detectors.py            # Threat detection rules engine
│   └── reporter.py             # HTML dashboard generator
├── logs/
│   └── samples/
│       ├── apache_access.log   # Sample Apache log with injected attacks
│       └── auth.log            # Sample SSH auth log with brute force
├── reports/                    # Generated HTML reports (gitignored)
├── tests/
│   └── test_detectors.py       # 15+ unit tests (pytest)
├── .github/
│   └── workflows/ci.yml        # GitHub Actions CI
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/Tachow/siem-log-analyser.git
cd siem-log-analyser

# 2. Install dependencies (only needed for Plotly/Pandas extras)
pip install -r requirements.txt

# 3. Run against sample logs
python main.py --apache logs/samples/apache_access.log --ssh logs/samples/auth.log

# 4. Open the report
open reports/report.html      # macOS
xdg-open reports/report.html  # Linux
```

**CLI options:**

```
usage: main.py [-h] [--apache FILE] [--ssh FILE] [--output FILE] [--no-report]

  --apache FILE    Apache access log path
  --ssh FILE       SSH auth.log path
  --output FILE    Output HTML path (default: reports/report.html)
  --no-report      Print alerts to stdout only, skip HTML
```

---

## 🔍 Detection Rules

### HTTP / Apache

| Rule | Trigger | Severity |
|---|---|---|
| Brute Force (HTTP) | 5+ failed auth (401/403) from same IP within 10s | HIGH |
| SQL Injection | SQLi patterns in request path (`' OR`, `UNION SELECT`, etc.) | CRITICAL |
| XSS Attempt | XSS patterns in request path (`<script`, `onerror=`, etc.) | HIGH |
| Sensitive Path Access | Requests to `/.env`, `/admin`, `/.git`, `/phpmyadmin` | HIGH |
| Suspicious User-Agent | Known scanner UA strings (sqlmap, nikto, masscan) | MEDIUM |

### SSH / auth.log

| Rule | Trigger | Severity |
|---|---|---|
| SSH Brute Force | 5+ failed passwords from same IP within 30s | CRITICAL |
| Successful Login After Failures | Login success after 3+ failures from same IP | CRITICAL |
| User Enumeration | 3+ distinct invalid usernames from same IP | HIGH |

> Thresholds are easy to tune — see `src/detectors.py` function arguments.

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

```
tests/test_detectors.py::TestApacheParser::test_valid_line          PASSED
tests/test_detectors.py::TestSSHParser::test_failed_password        PASSED
tests/test_detectors.py::TestHTTPBruteForce::test_triggers_on_threshold  PASSED
tests/test_detectors.py::TestSQLiDetection::test_sqli_in_path       PASSED
tests/test_detectors.py::TestSSHBruteForce::test_success_after_failures_flagged  PASSED
... 15 passed in 0.12s
```

---

## 🚀 Extension Ideas (PRs Welcome)

- [ ] **Sigma rule support** — parse `.yml` Sigma rules and apply them as dynamic detectors
- [ ] **Windows Event Log parser** — ingest XML `.evtx` exports
- [ ] **IP reputation lookup** — query AbuseIPDB / VirusTotal API for threat intel enrichment
- [ ] **Slack/email alerting** — push CRITICAL alerts to a webhook in real time
- [ ] **Streaming mode** — `tail -f` live log files with `watchdog`
- [ ] **GeoIP mapping** — map source IPs to countries using `geoip2`

---

## 🛠 Technical Design

```
Apache Log ──┐                    ┌── Alert list ──┐
             ├──▶ parsers.py ──▶ detectors.py       ├──▶ reporter.py ──▶ report.html
SSH Log ─────┘   (dataclasses)   (rule engine)      │
                                                     └── stdout summary
```

- **Parsers** use `re` and `dataclasses` — typed, testable, zero-dependency
- **Detectors** are pure functions: `list[LogEntry] → list[Alert]` — easy to unit-test and extend
- **Reporter** writes a single self-contained HTML file using Chart.js from CDN — no server needed

---

## 🔗 Related Projects

- [CryptoSafe](https://github.com/Tachow/CryptoSafe) — AES/RSA/ECDH encryption app in Java
- [Brain Tumour Detection CNN](https://github.com/Tachow/Brain-Tumor-Detection-using-MRI-Images) — 97.44% accuracy deep learning classifier

---

## 📄 Licence

MIT — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Tanvir Ahmed Chowdhury**  
MIT Cyber Security, Macquarie University  
[LinkedIn](https://www.linkedin.com/in/tanvir-ahmed-chowdhury-80350790/) · [GitHub](https://github.com/Tachow)
