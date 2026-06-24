#!/usr/bin/env python3
"""
main.py — SIEM Log Analyser CLI

Usage:
    python main.py --apache logs/samples/apache_access.log --ssh logs/samples/auth.log
    python main.py --apache logs/access.log --output reports/my_report.html
    python main.py --help
"""

import argparse
import sys
from pathlib import Path

# Ensure src/ is importable when run from project root
sys.path.insert(0, str(Path(__file__).parent / "src"))

from parsers import parse_apache_log, parse_ssh_log
from detectors import run_apache_detectors, run_ssh_detectors
from reporter import generate_report


BANNER = r"""
  ____  ___ ___ __  __   _                    _                    
 / ___|_ _| __||  \/  | | |    ___   __ _    / \   _ __   __ _ ___ 
 \___ \| || _| | |\/| | | |   / _ \ / _` |  / _ \ | '_ \ / _` / __|
  ___) | || |__| |  | | | |__| (_) | (_| | / ___ \| | | | (_| \__ \\
 |____/___|____|_|  |_| |_____\___/ \__, |/_/   \_\_| |_|\__,_|___/
                                    |___/                            
  Python SIEM Log Analyser  |  github.com/Tachow
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyse Apache and SSH logs for security threats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--apache", metavar="FILE", help="Apache access log file path")
    p.add_argument("--ssh",    metavar="FILE", help="SSH auth log file path")
    p.add_argument("--output", metavar="FILE", default="reports/report.html",
                   help="Output HTML report path (default: reports/report.html)")
    p.add_argument("--no-report", action="store_true", help="Skip HTML report, print alerts only")
    return p.parse_args()


def main() -> None:
    print(BANNER)
    args = parse_args()

    if not args.apache and not args.ssh:
        print("[!] Provide at least one log source: --apache and/or --ssh\n")
        sys.exit(1)

    all_alerts = []
    sources = []
    total_events = 0

    # --- Apache ---
    if args.apache:
        path = args.apache
        if not Path(path).exists():
            print(f"[!] Apache log not found: {path}")
            sys.exit(1)
        print(f"[*] Parsing Apache access log: {path}")
        apache_entries = parse_apache_log(path)
        total_events += len(apache_entries)
        print(f"    → {len(apache_entries)} entries parsed")
        apache_alerts = run_apache_detectors(apache_entries)
        all_alerts.extend(apache_alerts)
        sources.append(Path(path).name)
        print(f"    → {len(apache_alerts)} alerts generated")

    # --- SSH ---
    if args.ssh:
        path = args.ssh
        if not Path(path).exists():
            print(f"[!] SSH auth log not found: {path}")
            sys.exit(1)
        print(f"[*] Parsing SSH auth log: {path}")
        ssh_entries = parse_ssh_log(path)
        total_events += len(ssh_entries)
        print(f"    → {len(ssh_entries)} entries parsed")
        ssh_alerts = run_ssh_detectors(ssh_entries)
        all_alerts.extend(ssh_alerts)
        sources.append(Path(path).name)
        print(f"    → {len(ssh_alerts)} alerts generated")

    # --- Summary ---
    print(f"\n{'='*60}")
    from collections import Counter
    sev_counts = Counter(a.severity for a in all_alerts)
    print(f"  TOTAL ALERTS : {len(all_alerts)}")
    print(f"  CRITICAL     : {sev_counts.get('CRITICAL', 0)}")
    print(f"  HIGH         : {sev_counts.get('HIGH', 0)}")
    print(f"  MEDIUM       : {sev_counts.get('MEDIUM', 0)}")
    print(f"{'='*60}\n")

    if all_alerts:
        print("  Top alerts:")
        for a in sorted(all_alerts, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.severity,4))[:5]:
            print(f"  [{a.severity:<8}] {a.category:<35} src={a.source_ip}")

    # --- Report ---
    if not args.no_report:
        print(f"\n[*] Generating HTML report → {args.output}")
        report_path = generate_report(
            alerts=all_alerts,
            sources=sources,
            total_events=total_events,
            output_path=args.output,
        )
        print(f"[+] Report written to: {report_path}")
    else:
        print("\n[*] --no-report flag set, skipping HTML generation.")

    print("\n[+] Analysis complete.\n")


if __name__ == "__main__":
    main()
