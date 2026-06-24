"""
reporter.py — Generates a self-contained HTML dashboard from analysis results.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Sequence

from detectors import Alert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_order(s: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 5)


def _badge(severity: str) -> str:
    colours = {
        "CRITICAL": ("#7b1a1a", "#f8d7da"),
        "HIGH":     ("#7d3c00", "#fde8cc"),
        "MEDIUM":   ("#6b5a00", "#fff3cd"),
        "LOW":      ("#0b3d6b", "#d6eaf8"),
        "INFO":     ("#4a4a4a", "#f0f0f0"),
    }
    fg, bg = colours.get(severity, ("#333", "#eee"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 8px;'
        f'border-radius:4px;font-size:12px;font-weight:600;">{severity}</span>'
    )


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIEM Log Analysis Report — {generated}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f1117; color: #e2e8f0; }}
  header {{ background: #1a1d2e; padding: 24px 40px; border-bottom: 1px solid #2d3748;
            display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ margin: 0; font-size: 22px; font-weight: 600; color: #e2e8f0; }}
  header .meta {{ font-size: 13px; color: #718096; text-align: right; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: #1a1d2e; border: 1px solid #2d3748; border-radius: 10px;
                padding: 18px; text-align: center; }}
  .stat-card .val {{ font-size: 32px; font-weight: 700; margin-bottom: 4px; }}
  .stat-card .lbl {{ font-size: 12px; color: #718096; text-transform: uppercase; letter-spacing: .08em; }}
  .stat-card.critical .val {{ color: #fc8181; }}
  .stat-card.high     .val {{ color: #f6ad55; }}
  .stat-card.medium   .val {{ color: #fbd38d; }}
  .stat-card.total    .val {{ color: #63b3ed; }}
  .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
  .chart-card {{ background: #1a1d2e; border: 1px solid #2d3748; border-radius: 10px; padding: 20px; }}
  .chart-card h3 {{ margin: 0 0 16px; font-size: 14px; font-weight: 600; color: #a0aec0;
                    text-transform: uppercase; letter-spacing: .06em; }}
  .section-title {{ font-size: 16px; font-weight: 600; color: #a0aec0; margin: 0 0 12px;
                    text-transform: uppercase; letter-spacing: .06em; }}
  .alert-table {{ width: 100%; border-collapse: collapse; background: #1a1d2e;
                  border: 1px solid #2d3748; border-radius: 10px; overflow: hidden; }}
  .alert-table th {{ background: #252840; padding: 12px 16px; font-size: 12px;
                     text-transform: uppercase; letter-spacing: .06em; color: #718096;
                     font-weight: 600; text-align: left; }}
  .alert-table td {{ padding: 12px 16px; border-top: 1px solid #2d3748;
                     font-size: 13px; vertical-align: top; }}
  .alert-table tr:hover td {{ background: #1f2235; }}
  .ip-tag {{ background: #2d3748; padding: 2px 8px; border-radius: 4px;
             font-family: monospace; font-size: 12px; }}
  .evidence {{ font-family: monospace; font-size: 11px; color: #718096;
               background: #0f1117; padding: 6px 10px; border-radius: 4px;
               margin-top: 6px; white-space: pre-wrap; word-break: break-all; }}
  .top-ips {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
  .ip-card {{ background: #1a1d2e; border: 1px solid #2d3748; border-radius: 10px; padding: 20px; }}
  .ip-row {{ display: flex; justify-content: space-between; align-items: center;
             padding: 8px 0; border-top: 1px solid #2d3748; font-size: 13px; }}
  .ip-row:first-child {{ border-top: none; }}
  .bar {{ height: 6px; border-radius: 3px; margin-top: 4px; }}
  footer {{ text-align: center; padding: 24px; color: #4a5568; font-size: 12px;
            border-top: 1px solid #2d3748; margin-top: 40px; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡 SIEM Log Analysis Report</h1>
    <div style="font-size:13px;color:#718096;margin-top:4px;">Python SIEM Log Analyser — github.com/Tachow</div>
  </div>
  <div class="meta">
    Generated: {generated}<br>
    Log sources: {sources}<br>
    Total events parsed: {total_events:,}
  </div>
</header>

<div class="container">

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card critical"><div class="val">{count_critical}</div><div class="lbl">Critical</div></div>
    <div class="stat-card high"><div class="val">{count_high}</div><div class="lbl">High</div></div>
    <div class="stat-card medium"><div class="val">{count_medium}</div><div class="lbl">Medium</div></div>
    <div class="stat-card total"><div class="val">{count_total}</div><div class="lbl">Total Alerts</div></div>
    <div class="stat-card" style=""><div class="val" style="color:#68d391;">{unique_ips}</div><div class="lbl">Unique Threat IPs</div></div>
  </div>

  <!-- Charts -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>Alerts by Severity</h3>
      <canvas id="severityChart" height="220"></canvas>
    </div>
    <div class="chart-card">
      <h3>Alerts by Category</h3>
      <canvas id="categoryChart" height="220"></canvas>
    </div>
  </div>

  <!-- Top threat IPs -->
  <div class="top-ips">
    <div class="ip-card">
      <div class="section-title" style="margin-bottom:12px;">Top Threat IPs</div>
      {top_ips_html}
    </div>
    <div class="ip-card">
      <div class="section-title" style="margin-bottom:12px;">Category Breakdown</div>
      {category_breakdown_html}
    </div>
  </div>

  <!-- Alert table -->
  <div class="section-title">All Alerts ({count_total})</div>
  <table class="alert-table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Source IP</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {alert_rows}
    </tbody>
  </table>

</div>

<footer>Generated by Python SIEM Log Analyser &nbsp;|&nbsp; Tanvir Chowdhury &nbsp;|&nbsp; {generated}</footer>

<script>
const sevData = {severity_chart_data};
const catData = {category_chart_data};

new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: sevData.labels,
    datasets: [{{ data: sevData.values,
      backgroundColor: ['#fc8181','#f6ad55','#fbd38d','#63b3ed','#a0aec0'],
      borderWidth: 0 }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#a0aec0', font: {{ size: 12 }} }} }} }},
              maintainAspectRatio: false }}
}});

new Chart(document.getElementById('categoryChart'), {{
  type: 'bar',
  data: {{
    labels: catData.labels,
    datasets: [{{ data: catData.values, backgroundColor: '#4299e1', borderRadius: 4 }}]
  }},
  options: {{
    indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#718096' }}, grid: {{ color: '#2d3748' }} }},
      y: {{ ticks: {{ color: '#a0aec0', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }},
    maintainAspectRatio: false
  }}
}});
</script>
</body>
</html>
"""


def generate_report(
    alerts: list[Alert],
    sources: list[str],
    total_events: int,
    output_path: str = "reports/report.html",
) -> str:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = Counter(a.severity for a in alerts)
    cat_counts = Counter(a.category for a in alerts)
    ip_counts = Counter(a.source_ip for a in alerts)

    # Top IPs
    top_ips_html = ""
    max_ip_count = max(ip_counts.values(), default=1)
    for ip, cnt in ip_counts.most_common(6):
        pct = int(cnt / max_ip_count * 100)
        top_ips_html += (
            f'<div class="ip-row"><div>'
            f'<span class="ip-tag">{ip}</span>'
            f'<div class="bar" style="width:{pct}%;background:#4299e1;"></div></div>'
            f'<span style="color:#718096;">{cnt}</span></div>'
        )

    # Category breakdown
    cat_html = ""
    for cat, cnt in cat_counts.most_common():
        cat_html += (
            f'<div class="ip-row">'
            f'<span style="font-size:13px;">{cat}</span>'
            f'<span style="color:#718096;">{cnt}</span></div>'
        )

    # Alert rows
    alert_rows = ""
    for a in sorted(alerts, key=lambda x: _severity_order(x.severity)):
        evidence_html = ""
        for ev in a.evidence[:2]:
            evidence_html += f'<div class="evidence">{ev}</div>'
        alert_rows += (
            f"<tr><td>{a.timestamp.strftime('%H:%M:%S')}</td>"
            f"<td>{_badge(a.severity)}</td>"
            f"<td>{a.category}</td>"
            f"<td><span class='ip-tag'>{a.source_ip}</span></td>"
            f"<td>{a.description}{evidence_html}</td></tr>"
        )

    # Chart data
    sev_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_values = [counts.get(s, 0) for s in sev_labels]
    cat_labels = [k for k, _ in cat_counts.most_common(8)]
    cat_values = [cat_counts[k] for k in cat_labels]

    html = HTML_TEMPLATE.format(
        generated=generated,
        sources=", ".join(sources),
        total_events=total_events,
        count_critical=counts.get("CRITICAL", 0),
        count_high=counts.get("HIGH", 0),
        count_medium=counts.get("MEDIUM", 0),
        count_total=len(alerts),
        unique_ips=len(ip_counts),
        top_ips_html=top_ips_html,
        category_breakdown_html=cat_html,
        alert_rows=alert_rows,
        severity_chart_data=json.dumps({"labels": sev_labels, "values": sev_values}),
        category_chart_data=json.dumps({"labels": cat_labels, "values": cat_values}),
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html, encoding="utf-8")
    return output_path

