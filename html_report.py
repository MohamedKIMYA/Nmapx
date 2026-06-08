import html
from datetime import datetime
from typing import List, Dict


def export_html(results: List[Dict], path: str):
    def esc(value):
        return html.escape(str(value) if value is not None else "")

    now = datetime.now().isoformat(sep=" ", timespec="seconds")
    summary_rows = []
    port_rows = []
    cve_sections = []
    event_sections = []

    for res in results:
        open_count = sum(1 for p in res.get("ports", []) if "open" in p.get("state", ""))
        cve_count = sum(len(p.get("cves", [])) for p in res.get("ports", []))
        summary_rows.append(
            f"<tr data-search=\"{esc(res.get('target',''))} {esc(res.get('profile',''))} {esc(res.get('os',''))} {esc(','.join(sorted({e.get('type','') for e in res.get('events', []) if e.get('type')})))}\">"
            f"<td>{esc(res.get('target', ''))}</td>"
            f"<td>{esc(res.get('profile', ''))}</td>"
            f"<td>{esc(res.get('sid', ''))}</td>"
            f"<td>{esc(res.get('os', ''))}</td>"
            f"<td>{open_count}</td>"
            f"<td>{cve_count}</td>"
            f"<td>{esc(','.join(sorted({e.get('type','') for e in res.get('events', []) if e.get('type')})))}</td>"
            f"</tr>"
        )

        for p in res.get("ports", []):
            cves = p.get("cves", []) or []
            port_rows.append(
                f"<tr data-search=\"{esc(res.get('target',''))} {esc(p.get('port',''))} {esc(p.get('service',''))} {esc(p.get('version',''))} {esc(p.get('cpe',''))}\">"
                f"<td>{esc(res.get('target',''))}</td>"
                f"<td>{esc(p.get('port',''))}</td>"
                f"<td>{esc(p.get('proto',''))}</td>"
                f"<td>{esc(p.get('state',''))}</td>"
                f"<td>{esc(p.get('service',''))}</td>"
                f"<td>{esc(p.get('version',''))}</td>"
                f"<td>{esc(p.get('cpe',''))}</td>"
                f"<td>{len(cves)}</td>"
                f"</tr>"
            )
            for cve in cves:
                severity = esc(cve.get('severity', ''))
                cve_sections.append(
                    f"<tr class=\"sev-{severity}\" data-search=\"{esc(res.get('target',''))} {esc(p.get('service',''))} {esc(cve.get('id',''))} {severity}\" data-severity=\"{severity}\">"
                    f"<td>{esc(res.get('target',''))}</td>"
                    f"<td>{esc(p.get('port',''))}</td>"
                    f"<td>{esc(cve.get('id',''))}</td>"
                    f"<td>{severity}</td>"
                    f"<td>{esc(cve.get('score',''))}</td>"
                    f"<td>{esc(cve.get('query',''))}</td>"
                    f"<td>{esc(cve.get('confidence',''))}</td>"
                    f"<td>{esc(cve.get('desc',''))}</td>"
                    f"</tr>"
                )

        for event in res.get("events", []):
            event_sections.append(
                f"<tr data-search=\"{esc(res.get('target',''))} {esc(event.get('type',''))} {esc(event.get('port', {}).get('service','') if isinstance(event.get('port'), dict) else '')} {esc(event.get('cve', {}).get('id','') if isinstance(event.get('cve'), dict) else '')}\">"
                f"<td>{esc(res.get('target',''))}</td>"
                f"<td>{esc(event.get('type',''))}</td>"
                f"<td>{esc(event.get('port', {}).get('port','') if isinstance(event.get('port'), dict) else '')}</td>"
                f"<td>{esc(event.get('port', {}).get('service','') if isinstance(event.get('port'), dict) else '')}</td>"
                f"<td>{esc(event.get('old', {}).get('version','') if isinstance(event.get('old'), dict) else '')}</td>"
                f"<td>{esc(event.get('cve', {}).get('id','') if isinstance(event.get('cve'), dict) else '')}</td>"
                f"</tr>"
            )

    html_content = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>NmapX Report</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f4f6fb; color: #1f2937; margin: 0; padding: 24px; }}
header {{ margin-bottom: 24px; }}
h1 {{ margin-bottom: 8px; color: #1f2937; }}
h2 {{ margin-top: 32px; color: #1f2937; }}
.toolbar {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }}
.toolbar input, .toolbar select {{ padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 8px; min-width: 220px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); background: #fff; }}
th, td {{ border: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; }}
th {{ background: #e0e7ff; color: #1e3a8a; }}
tr:nth-child(even) {{ background: #f8fafc; }}
tr.sev-CRITICAL {{ background: #fee2e2; }}
tr.sev-HIGH {{ background: #fef3c7; }}
tr.sev-MEDIUM {{ background: #dbeafe; }}
tr.sev-LOW {{ background: #dcfce7; }}
tr.sev-N/A {{ background: #e5e7eb; }}
.details-box {{ border: 1px solid #cbd5e1; background: #fff; border-radius: 12px; padding: 16px; margin-bottom: 24px; }}
code {{ font-family: Consolas, monospace; background: #f1f5f9; padding: 2px 4px; border-radius: 4px; }}
</style>
</head>
<body>
<header>
  <h1>NmapX HTML Report</h1>
  <p>Generated: <strong>{esc(now)}</strong></p>
  <div class=\"toolbar\">
    <input id=\"search-input\" type=\"search\" placeholder=\"Search target, port, service, CVE, type...\" oninput=\"filterTables()\" />
    <select id=\"severity-filter\" onchange=\"filterTables()\">
      <option value=\"all\">All severities</option>
      <option value=\"CRITICAL\">CRITICAL</option>
      <option value=\"HIGH\">HIGH</option>
      <option value=\"MEDIUM\">MEDIUM</option>
      <option value=\"LOW\">LOW</option>
      <option value=\"N/A\">N/A</option>
    </select>
  </div>
</header>
<section class=\"details-box\">
  <details open>
    <summary><strong>Target Summary</strong></summary>
    <table>
      <thead><tr><th>Target</th><th>Profile</th><th>Session</th><th>OS Hint</th><th>Open Ports</th><th>Potential CVEs</th><th>Events</th></tr></thead>
      <tbody>
        {''.join(summary_rows)}
      </tbody>
    </table>
  </details>
</section>
<section class=\"details-box\">
  <details>
    <summary><strong>Port Details</strong></summary>
    <table>
      <thead><tr><th>Target</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>CPE</th><th>CVE Count</th></tr></thead>
      <tbody>
        {''.join(port_rows)}
      </tbody>
    </table>
  </details>
</section>
<section class=\"details-box\">
  <details>
    <summary><strong>Potential CVE Matches</strong></summary>
    <table>
      <thead><tr><th>Target</th><th>Port</th><th>CVE</th><th>Severity</th><th>Score</th><th>Query</th><th>Confidence</th><th>Description</th></tr></thead>
      <tbody>
        {''.join(cve_sections)}
      </tbody>
    </table>
  </details>
</section>
<section class=\"details-box\">
  <details>
    <summary><strong>Events</strong></summary>
    <table>
      <thead><tr><th>Target</th><th>Type</th><th>Port</th><th>Service</th><th>Old Version</th><th>CVE ID</th></tr></thead>
      <tbody>
        {''.join(event_sections)}
      </tbody>
    </table>
  </details>
</section>
<script>
function filterTables() {{
  const query = document.getElementById('search-input').value.toLowerCase();
  const severity = document.getElementById('severity-filter').value;
  document.querySelectorAll('tbody tr').forEach(row => {{
    const text = row.getAttribute('data-search')?.toLowerCase() || '';
    const rowSeverity = row.getAttribute('data-severity') || '';
    const matchesSearch = !query || text.includes(query);
    const matchesSeverity = severity === 'all' || rowSeverity === severity;
    row.style.display = matchesSearch && matchesSeverity ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"  [OK] HTML -> {path}")
