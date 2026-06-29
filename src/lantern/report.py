from __future__ import annotations

from jinja2 import Template

from lantern.inventory import Inventory
from lantern.risk import score_observation


REPORT_TEMPLATE = Template(
    """# Lantern LAN Report

## Inventory

| IP | MAC | Hostname | Vendor | Risk | Services |
|---|---|---|---|---|---|
{% for row in rows -%}
| {{ row.device.ip }} | {{ row.device.mac or "" }} | {{ row.device.hostname or "" }} | {{ row.device.vendor or "" }} | {{ row.risk.level }} | {{ row.services }} |
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
3. Disable Telnet, UPnP, and exposed debug/admin services where possible.
4. Re-run Lantern after remediation and keep the new report as the baseline.
"""
)


def render_markdown_report(inventory: Inventory, baseline: str | None = None) -> str:
    devices = inventory.list_devices()
    rows = []
    for device in devices:
        rows.append(
            {
                "device": device,
                "risk": score_observation(device),
                "services": ", ".join(port.label for port in device.ports),
            }
        )
    diff = inventory.diff_against_baseline(baseline) if baseline else None
    return REPORT_TEMPLATE.render(rows=rows, baseline=baseline, diff=diff).strip() + "\n"
