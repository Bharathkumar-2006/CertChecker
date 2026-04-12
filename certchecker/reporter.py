"""
Report exporter: JSON, CSV, and HTML output formats.
"""

import json
import csv
import io
import datetime
from typing import List, Optional


def export_json(results: List[dict], output_path: Optional[str] = None) -> str:
    """Export results to JSON format."""
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "count": len(results),
        "results": results,
    }
    json_str = json.dumps(data, indent=2, default=str)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


def export_csv(results: List[dict], output_path: Optional[str] = None) -> str:
    """Export results to CSV format."""
    if not results:
        return ""

    # Flatten nested fields into CSV-friendly columns
    rows = []
    for r in results:
        row = {
            "hostname": r.get("hostname", ""),
            "port": r.get("port", 443),
            "resolved_ip": r.get("resolved_ip", ""),
            "is_valid": r.get("is_valid", ""),
            "is_expired": r.get("is_expired", ""),
            "days_remaining": r.get("days_remaining", ""),
            "not_before": r.get("not_before", ""),
            "not_after": r.get("not_after", ""),
            "subject_cn": r.get("subject", {}).get("CN", ""),
            "subject_o": r.get("subject", {}).get("O", ""),
            "issuer_cn": r.get("issuer", {}).get("CN", ""),
            "issuer_o": r.get("issuer", {}).get("O", ""),
            "is_self_signed": r.get("is_self_signed", ""),
            "tls_version": r.get("tls_version", ""),
            "cipher_suite": r.get("cipher_suite", ""),
            "key_type": r.get("key_type", ""),
            "key_bits": r.get("key_bits", ""),
            "signature_algorithm": r.get("signature_algorithm", ""),
            "is_weak_signature": r.get("is_weak_signature", ""),
            "sans": "; ".join(r.get("sans", [])),
            "weaknesses": "; ".join(r.get("weaknesses", [])),
            "checked_at": r.get("checked_at", ""),
        }
        rows.append(row)

    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    csv_str = buf.getvalue()
    if output_path:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write(csv_str)
    return csv_str


def export_html(results: List[dict], output_path: Optional[str] = None) -> str:
    """Export results to a styled HTML report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    valid_count = sum(1 for r in results if r.get("is_valid"))
    expired_count = sum(1 for r in results if r.get("is_expired"))
    warning_count = sum(1 for r in results if not r.get("is_expired") and 0 < r.get("days_remaining", 999) <= 30)
    critical_count = sum(1 for r in results if not r.get("is_expired") and 0 < r.get("days_remaining", 999) <= 7)

    rows_html = ""
    for r in results:
        days = r.get("days_remaining", 0)
        if r.get("is_expired"):
            status_class = "expired"
            status_text = "EXPIRED"
        elif days <= 7:
            status_class = "critical"
            status_text = f"CRITICAL ({days}d)"
        elif days <= 30:
            status_class = "warning"
            status_text = f"WARNING ({days}d)"
        else:
            status_class = "valid"
            status_text = f"Valid ({days}d)"

        weaknesses = r.get("weaknesses", [])
        weaknesses_html = "".join(f'<li>{w}</li>' for w in weaknesses) if weaknesses else "<li>None</li>"
        sans = r.get("sans", [])
        sans_short = ", ".join(sans[:3]) + (f" +{len(sans)-3} more" if len(sans) > 3 else "")
        subject = r.get("subject", {})
        issuer = r.get("issuer", {})

        rows_html += f"""
        <tr>
            <td><strong>{r.get("hostname", "")}</strong><br><small class="ip">{r.get("resolved_ip", "")}</small></td>
            <td><span class="badge {status_class}">{status_text}</span></td>
            <td>{r.get("not_after", "—")}</td>
            <td>{subject.get("CN", subject.get("O", "—"))}<br><small>{issuer.get("CN", issuer.get("O", "—"))}</small></td>
            <td>{r.get("tls_version", "—")}<br><small>{r.get("cipher_suite", "")}</small></td>
            <td>{r.get("key_type", "—")} {r.get("key_bits", "")}b<br><small>{r.get("signature_algorithm", "")}</small></td>
            <td><small>{sans_short or "—"}</small></td>
            <td><ul class="weaknesses">{weaknesses_html}</ul></td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSL Certificate Report — {now}</title>
  <style>
    :root {{
      --bg: #0f1117;
      --surface: #1a1d27;
      --border: #2d3148;
      --text: #e2e8f0;
      --muted: #8892a4;
      --green: #22c55e;
      --yellow: #f59e0b;
      --orange: #f97316;
      --red: #ef4444;
      --blue: #3b82f6;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
    h1 {{ font-size: 1.8rem; margin-bottom: 0.3rem; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
    .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
    .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }}
    .stat-card .number {{ font-size: 2rem; font-weight: 700; }}
    .stat-card .label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
    .valid-num {{ color: var(--green); }}
    .expired-num {{ color: var(--red); }}
    .warning-num {{ color: var(--yellow); }}
    .critical-num {{ color: var(--orange); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 12px; overflow: hidden; }}
    thead {{ background: #1e2235; }}
    th {{ text-align: left; padding: 12px 16px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); border-bottom: 1px solid var(--border); }}
    td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 0.88rem; vertical-align: top; }}
    tr:hover td {{ background: rgba(59,130,246,0.05); }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }}
    .badge.valid {{ background: rgba(34,197,94,0.15); color: var(--green); }}
    .badge.warning {{ background: rgba(245,158,11,0.15); color: var(--yellow); }}
    .badge.critical {{ background: rgba(249,115,22,0.15); color: var(--orange); }}
    .badge.expired {{ background: rgba(239,68,68,0.15); color: var(--red); }}
    .ip {{ color: var(--muted); font-size: 0.78rem; }}
    ul.weaknesses {{ list-style: none; padding: 0; }}
    ul.weaknesses li {{ font-size: 0.78rem; color: var(--red); ::before {{ content: '⚠ '; }} }}
    ul.weaknesses li:first-child:last-child {{ color: var(--green); }}
    small {{ color: var(--muted); }}
    footer {{ margin-top: 2rem; text-align: center; color: var(--muted); font-size: 0.8rem; }}
  </style>
</head>
<body>
  <h1>🔒 SSL Certificate Report</h1>
  <p class="meta">Generated at {now} &nbsp;·&nbsp; {total} domain(s) checked</p>
  <div class="stats">
    <div class="stat-card"><div class="number valid-num">{valid_count}</div><div class="label">Valid</div></div>
    <div class="stat-card"><div class="number warning-num">{warning_count}</div><div class="label">Expiring</div></div>
    <div class="stat-card"><div class="number critical-num">{critical_count}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="number expired-num">{expired_count}</div><div class="label">Expired</div></div>
    <div class="stat-card"><div class="number" style="color:var(--blue)">{total}</div><div class="label">Total</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Host</th><th>Status</th><th>Expires</th><th>Subject / Issuer</th>
        <th>TLS / Cipher</th><th>Key</th><th>SANs</th><th>Weaknesses</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
  <footer>Generated by CertChecker CLI &mdash; SSL Certificate Inspection Tool</footer>
</body>
</html>"""

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
    return html
