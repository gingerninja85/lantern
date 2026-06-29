from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from jinja2 import Template

from lantern.inventory import Inventory, Observation
from lantern.risk import Risk, score_observation


REPORT_TEMPLATE = Template(
    """# Lantern LAN Report

## Summary

| Metric | Count |
|---|---:|
| Devices | {{ summary.devices }} |
| Open services | {{ summary.services }} |
| High risk devices | {{ summary.high }} |
| Medium risk devices | {{ summary.medium }} |
| Low risk devices | {{ summary.low }} |

## Inventory

| IP | MAC | Hostname | Vendor | Risk | Services |
|---|---|---|---|---|---|
{% for row in rows -%}
| {{ row.device.ip }} | {{ row.device.mac or "" }} | {{ row.device.hostname or "" }} | {{ row.device.vendor or "" }} | {{ row.risk.level }} ({{ row.risk.score }}) | {{ row.services }} |
{% endfor %}
{% if baseline %}
## Changes vs `{{ baseline }}`

### New devices
{% if diff.new_devices -%}
{% for device in diff.new_devices -%}
- `{{ device.ip }}` {{ device.hostname or "" }} {{ device.mac or "" }} {{ device.vendor or "" }}
{% endfor -%}
{% else -%}
- None
{% endif %}

### New ports
{% if diff.new_ports -%}
{% for change in diff.new_ports -%}
- `{{ change.ip }}` {{ change.hostname or "" }}: {{ change.port.label }}{% if change.port.product %} — {{ change.port.product }}{% endif %}
{% endfor -%}
{% else -%}
- None
{% endif %}
{% endif %}

## Findings
{% for row in rows -%}
{% if row.risk.findings -%}
### {{ row.device.ip }} {{ row.device.hostname or "" }}
{% for finding in row.risk.findings -%}
- {{ finding }}
{% endfor -%}
{% endif -%}
{% endfor %}

## Recommended next steps

1. Label every known device by owner/function in your router or Lantern notes.
2. Move unknown or risky IoT devices to a guest/IoT VLAN.
3. Disable Telnet, UPnP, RDP, RTSP, and exposed debug/admin services where possible.
4. Re-run Lantern after remediation and keep the new report as the baseline.
"""
)

HTML_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Lantern LAN Report</title>
<style>
:root {
  --bg: #070912;
  --panel: rgba(15, 23, 42, 0.82);
  --panel-2: rgba(2, 6, 23, 0.78);
  --text: #e5f7ff;
  --muted: #8aa4b5;
  --cyan: #22d3ee;
  --pink: #fb37a5;
  --green: #5eead4;
  --yellow: #facc15;
  --red: #fb7185;
  --border: rgba(34, 211, 238, 0.28);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    radial-gradient(circle at top left, rgba(251, 55, 165, 0.18), transparent 32rem),
    radial-gradient(circle at 80% 10%, rgba(34, 211, 238, 0.16), transparent 30rem),
    linear-gradient(135deg, #050711 0%, #0f172a 52%, #09090b 100%);
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  opacity: 0.18;
  background-image: linear-gradient(rgba(34, 211, 238, 0.16) 1px, transparent 1px), linear-gradient(90deg, rgba(34, 211, 238, 0.16) 1px, transparent 1px);
  background-size: 42px 42px;
  mask-image: linear-gradient(to bottom, black, transparent 78%);
}
main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 64px; position: relative; }
.hero {
  border: 1px solid var(--border);
  border-radius: 28px;
  padding: 32px;
  background: linear-gradient(145deg, rgba(15, 23, 42, 0.88), rgba(2, 6, 23, 0.72));
  box-shadow: 0 0 0 1px rgba(251, 55, 165, 0.12), 0 24px 80px rgba(0, 0, 0, 0.42);
  overflow: hidden;
}
.kicker { color: var(--green); text-transform: uppercase; letter-spacing: 0.24em; font-size: 0.78rem; font-weight: 800; }
h1 { margin: 10px 0 10px; font-size: clamp(2.4rem, 8vw, 5.4rem); line-height: 0.9; letter-spacing: -0.08em; }
.gradient { background: linear-gradient(90deg, var(--cyan), var(--pink)); -webkit-background-clip: text; color: transparent; }
.subtitle { color: var(--muted); max-width: 760px; font-size: 1.05rem; line-height: 1.6; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-top: 28px; }
.stat { padding: 18px; border: 1px solid var(--border); border-radius: 18px; background: rgba(2, 6, 23, 0.52); }
.stat strong { display: block; font-size: 2rem; color: var(--cyan); }
.stat span { color: var(--muted); font-size: 0.88rem; }
section { margin-top: 28px; padding: 24px; border: 1px solid var(--border); border-radius: 22px; background: var(--panel); box-shadow: 0 18px 48px rgba(0, 0, 0, 0.22); }
h2 { margin: 0 0 18px; letter-spacing: -0.03em; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 820px; }
th, td { text-align: left; padding: 13px 12px; border-bottom: 1px solid rgba(148, 163, 184, 0.16); vertical-align: top; }
th { color: var(--cyan); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.12em; }
code, .mono { font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace; }
.badge { display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 10px; font-weight: 800; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }
.badge.high { color: #fff; background: linear-gradient(90deg, #e11d48, #fb7185); }
.badge.medium { color: #111827; background: linear-gradient(90deg, #facc15, #fb923c); }
.badge.low { color: #001514; background: linear-gradient(90deg, #5eead4, #22d3ee); }
.badge.info { color: #cbd5e1; background: rgba(148, 163, 184, 0.18); }
.finding { margin: 10px 0; padding: 12px 14px; border-left: 3px solid var(--pink); background: var(--panel-2); border-radius: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
.card { padding: 16px; border-radius: 16px; background: var(--panel-2); border: 1px solid rgba(148, 163, 184, 0.16); }
ol { padding-left: 1.3rem; color: var(--muted); line-height: 1.7; }
a { color: var(--cyan); }
.footer { color: var(--muted); margin-top: 22px; text-align: center; font-size: 0.85rem; }
</style>
</head>
<body>
<main>
  <header class="hero">
    <div class="kicker">Lantern // LAN risk telemetry</div>
    <h1><span class="gradient">Light up</span><br />the unknown.</h1>
    <p class="subtitle">Scanner evidence turned into a readable home-network inventory, baseline diff, and risk report. Defensive use only: networks you own or are authorized to assess.</p>
    <div class="stats">
      <div class="stat"><strong>{{ summary.devices }}</strong><span>devices</span></div>
      <div class="stat"><strong>{{ summary.services }}</strong><span>open services</span></div>
      <div class="stat"><strong>{{ summary.high }}</strong><span>high risk</span></div>
      <div class="stat"><strong>{{ summary.medium }}</strong><span>medium risk</span></div>
      <div class="stat"><strong>{{ summary.low }}</strong><span>low risk</span></div>
    </div>
  </header>

  <section>
    <h2>Inventory</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Risk</th><th>Services</th></tr></thead>
        <tbody>
        {% for row in rows %}
          <tr>
            <td class="mono">{{ row.device.ip|e }}</td>
            <td class="mono">{{ (row.device.mac or "")|e }}</td>
            <td>{{ (row.device.hostname or "")|e }}</td>
            <td>{{ (row.device.vendor or "")|e }}</td>
            <td><span class="badge {{ row.risk.level }}">{{ row.risk.level }} {{ row.risk.score }}</span></td>
            <td>{{ row.services|e }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </section>

  {% if baseline %}
  <section>
    <h2>Changes vs <code>{{ baseline|e }}</code></h2>
    <div class="grid">
      <div class="card">
        <h3>New devices</h3>
        {% if diff.new_devices %}
          {% for device in diff.new_devices %}<div class="finding"><span class="mono">{{ device.ip|e }}</span> {{ (device.hostname or "")|e }} {{ (device.mac or "")|e }} {{ (device.vendor or "")|e }}</div>{% endfor %}
        {% else %}<p class="subtitle">None</p>{% endif %}
      </div>
      <div class="card">
        <h3>New ports</h3>
        {% if diff.new_ports %}
          {% for change in diff.new_ports %}<div class="finding"><span class="mono">{{ change.ip|e }}</span> {{ (change.hostname or "")|e }}: {{ change.port.label|e }}{% if change.port.product %} — {{ change.port.product|e }}{% endif %}</div>{% endfor %}
        {% else %}<p class="subtitle">None</p>{% endif %}
      </div>
    </div>
  </section>
  {% endif %}

  <section>
    <h2>Findings</h2>
    {% set any_findings = namespace(value=false) %}
    {% for row in rows %}
      {% if row.risk.findings %}
        {% set any_findings.value = true %}
        <div class="card">
          <h3><span class="mono">{{ row.device.ip|e }}</span> {{ (row.device.hostname or "")|e }}</h3>
          {% for finding in row.risk.findings %}<div class="finding">{{ finding|e }}</div>{% endfor %}
        </div>
      {% endif %}
    {% endfor %}
    {% if not any_findings.value %}<p class="subtitle">No obvious risky service findings.</p>{% endif %}
  </section>

  <section>
    <h2>Recommended next steps</h2>
    <ol>
      <li>Label every known device by owner/function in your router or Lantern notes.</li>
      <li>Move unknown or risky IoT devices to a guest/IoT VLAN.</li>
      <li>Disable Telnet, UPnP, RDP, RTSP, and exposed debug/admin services where possible.</li>
      <li>Re-run Lantern after remediation and keep the new report as the baseline.</li>
    </ol>
  </section>
  <p class="footer">Generated by Lantern. Keep the light pointed at your own network.</p>
</main>
</body>
</html>
"""
)


@dataclass(frozen=True)
class ReportRow:
    device: Observation
    risk: Risk
    services: str


def _report_rows(inventory: Inventory) -> list[ReportRow]:
    rows = []
    for device in inventory.list_devices():
        risk = score_observation(device)
        rows.append(
            ReportRow(
                device=device,
                risk=risk,
                services=", ".join(port.label for port in device.ports),
            )
        )
    return sorted(rows, key=lambda row: (-row.risk.score, row.device.ip))


def _summary(rows: list[ReportRow]) -> dict[str, int]:
    levels = Counter(row.risk.level for row in rows)
    return {
        "devices": len(rows),
        "services": sum(len(row.device.ports) for row in rows),
        "high": levels["high"],
        "medium": levels["medium"],
        "low": levels["low"],
    }


def render_markdown_report(inventory: Inventory, baseline: str | None = None) -> str:
    rows = _report_rows(inventory)
    diff = inventory.diff_against_baseline(baseline) if baseline else None
    return REPORT_TEMPLATE.render(rows=rows, summary=_summary(rows), baseline=baseline, diff=diff).strip() + "\n"


def render_html_report(inventory: Inventory, baseline: str | None = None) -> str:
    rows = _report_rows(inventory)
    diff = inventory.diff_against_baseline(baseline) if baseline else None
    return HTML_TEMPLATE.render(rows=rows, summary=_summary(rows), baseline=baseline, diff=diff).strip() + "\n"
