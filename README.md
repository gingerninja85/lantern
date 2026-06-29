# Lantern

LAN inventory, diff, and risk tracker companion for network scanners.

Lantern does not try to be another scanner. It ingests evidence from tools like Nmap and ARP/neighbor tables, stores device history, detects changes, scores obvious risks, and emits human-readable reports.

## MVP goals

- Ingest Nmap XML service scans.
- Ingest ARP/neighbor observations from CSV.
- Track devices by MAC where available, falling back to IP when needed.
- Diff current observations against the previous baseline.
- Flag risky services such as Telnet, SMB, UPnP, and exposed admin HTTP.
- Emit Markdown reports suitable for Hermes/Telegram or later HTML dashboards.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

lantern ingest-arp examples/sample-arp.csv
lantern ingest-nmap examples/sample-nmap.xml
lantern baseline first-known-good
lantern report --baseline first-known-good
```

Real scan example:

```bash
# Optional but useful from WSL: export Windows neighbor cache to CSV.
powershell.exe -NoProfile -Command \
  "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Csv -NoTypeInformation" \
  > arp.csv

# Service scan.
nmap -Pn -sT -sV --version-all -oX scan.xml 192.168.1.0/24

# Ingest both evidence sources, then report.
lantern --db home.sqlite ingest-arp arp.csv
lantern --db home.sqlite ingest-nmap scan.xml
lantern --db home.sqlite report > reports/lan-report.md
```

## Commands

| Command | Purpose |
|---|---|
| `lantern ingest-arp arp.csv` | Ingest ARP/router/neighbor CSV into SQLite inventory |
| `lantern ingest-nmap scan.xml` | Ingest Nmap XML into SQLite inventory |
| `lantern baseline NAME` | Save current inventory as a named baseline |
| `lantern report [--baseline NAME]` | Print a Markdown risk/change report |

## Status

Early MVP. Built for defensive use on networks you own or are authorized to assess.
