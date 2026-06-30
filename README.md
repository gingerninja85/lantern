# 🔦 Lantern

<p align="center">
  <strong>Light up the unknown devices on your LAN.</strong><br />
  A defensive inventory, baseline-diff, and risk-report companion for Nmap, ARP, and router evidence.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-22d3ee?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-5eead4?style=for-the-badge" />
  <img alt="Defensive" src="https://img.shields.io/badge/use-defensive%20LAN%20inventory-fb37a5?style=for-the-badge" />
</p>

Lantern does **not** try to be another scanner. It ingests evidence from tools like Nmap and ARP/neighbor tables, stores device history, detects changes, scores obvious risks, and emits reports a human can act on.

```text
Nmap XML + ARP/router CSV ──▶ SQLite inventory ──▶ baseline diff + risk report
```

## Why Lantern exists

Most small network scanner projects stop at “here are the hosts and open ports.” Lantern is aimed at the next question:

> “What changed, what looks risky, and what should I fix first?”

## Features

- Native **safe TCP connect scanner** for Windows/Linux without requiring Nmap.
- Auto-discover Windows LAN devices from **Get-NetNeighbor** / local ARP evidence.
- Ingest **Nmap XML** service scans.
- Ingest **ARP/router/Windows neighbor CSV** exports.
- Track devices by **MAC address** where available, falling back to IP when needed.
- Merge WSL-style IP-only Nmap observations into MAC-backed ARP records.
- Save named baselines and flag **new devices** and **new ports**.
- Export inventory as **JSON or CSV**.
- Optional **Tkinter GUI** for people who prefer buttons over command-line flags.
- Score common home-network risks:
  - Telnet
  - SMB / NetBIOS
  - UPnP
  - RTSP camera streams
  - RDP
  - embedded/admin HTTP
  - CPE WAN management
- Emit plain Markdown or a polished cyberpunk-style standalone HTML report.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

# Native scanner path: discovers neighbors, scans common ports, writes HTML.
lantern --db home.sqlite scan --output reports/lantern.html

# Existing-evidence path.
lantern ingest-arp examples/sample-arp.csv
lantern ingest-nmap examples/sample-nmap.xml
lantern baseline first-known-good
lantern report --baseline first-known-good
lantern report --baseline first-known-good --format html --output reports/lantern.html
```

## Windows executable

Build standalone Windows binaries with PyInstaller from a Windows Python shell:

```powershell
py -3 -m pip install --user pyinstaller hatchling click jinja2 pytest ruff
py -3 -m pip install --user -e .
py -3 -m pytest -q
py -3 -m PyInstaller --clean --onefile --console --name lantern lantern_entry.py
py -3 -m PyInstaller --clean --onefile --windowed --name lantern-gui lantern_gui_entry.py
```

Run it from PowerShell:

```powershell
.\lantern-gui.exe
.\lantern.exe scan
.\lantern.exe scan --save-baseline known-good
.\lantern.exe scan --baseline known-good --output after.html
.\lantern.exe export --format csv --output devices.csv
```

## Real scan workflow

```bash
# Optional but useful from WSL: export Windows neighbor cache to CSV.
powershell.exe -NoProfile -Command \
  "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Csv -NoTypeInformation" \
  > arp.csv

# Service scan. Only scan networks you own or are authorized to assess.
nmap -Pn -sT -sV --version-light -oX scan.xml 192.168.1.0/24

# Ingest both evidence sources, then report.
lantern --db home.sqlite ingest-arp arp.csv
lantern --db home.sqlite ingest-nmap scan.xml
lantern --db home.sqlite baseline known-good
lantern --db home.sqlite report --baseline known-good > reports/lan-report.md
lantern --db home.sqlite report --baseline known-good --format html --output reports/lan-report.html
```

## Commands

| Command | Purpose |
|---|---|
| `lantern ingest-arp arp.csv` | Ingest ARP/router/neighbor CSV into SQLite inventory |
| `lantern ingest-nmap scan.xml` | Ingest Nmap XML into SQLite inventory |
| `lantern baseline NAME` | Save current inventory as a named baseline |
| `lantern report [--baseline NAME]` | Print a Markdown risk/change report |
| `lantern report --format html --output report.html` | Write a standalone styled HTML dashboard |

## Example output

```markdown
# Lantern LAN Report

## Summary

| Metric | Count |
|---|---:|
| Devices | 3 |
| Open services | 2 |
| High risk devices | 1 |

## Findings

### 192.168.1.20 ipc-cam
- Telnet exposed
- Embedded/admin HTTP service exposed
```

The HTML renderer turns the same evidence into a single-file dashboard with dark colors, neon accents, risk badges, and mobile-friendly layout.

## Design principles

- **Evidence-first.** Lantern stores observations from external tools instead of pretending to be the scanner of record.
- **Safe by default.** No credential guessing, brute forcing, or exploit checks.
- **Home-lab friendly.** Works well with WSL, router exports, and partial evidence.
- **Human-readable.** Reports should help you decide what to unplug, isolate, label, or harden.

## Similar projects researched

See [`docs/research.md`](docs/research.md) for notes from nearby GitHub projects and the improvement ideas that shaped the current roadmap.

## Development

```bash
pip install -e '.[dev]'
python -m pytest -q
python -m ruff check .
```

## Roadmap

- Device labels/owners and notes.
- JSON/CSV export.
- OUI vendor enrichment.
- Report screenshots/assets for GitHub README polish.
- Optional lightweight web dashboard.
- Scheduled scans and alert diff summaries.

## Safety boundary

Lantern is for **defensive use on networks you own or are explicitly authorized to assess**. It is an inventory and reporting companion, not an exploitation framework.

## License

MIT
