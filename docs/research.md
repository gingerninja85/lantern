# Similar project research

Lantern was compared against nearby GitHub projects in the home-network inventory / Nmap dashboard space on 2026-06-30.

## Repositories reviewed

| Repo | Notes | Improvement pulled into Lantern |
|---|---|---|
| [`Am1rX/netscout`](https://github.com/Am1rX/netscout) | ARP scanning, Nmap integration, HTML/JSON reporting. | Add first-class HTML reporting and keep JSON export on the roadmap. |
| [`evilkobayashi/network-inventory`](https://github.com/evilkobayashi/network-inventory) | Auto-discovery inventory, MAC vendor identification, searchable dashboard, CSV export. | Keep OUI/vendor enrichment and search/dashboard ideas on roadmap. |
| [`yairemartinez/nmap_dashboard`](https://github.com/yairemartinez/nmap_dashboard) | Flask dashboard for managing, tagging, and comparing Nmap scan results. | Baselines/diffs are a core Lantern primitive; device tagging should come next. |
| [`tamersaid2022/network-inventory-scanner`](https://github.com/tamersaid2022/network-inventory-scanner) | SNMP/SSH/ARP scanning, multi-format exports. | Lantern should stay scanner-agnostic but support more export formats. |
| [`AurevLan/NetLanVentory`](https://github.com/AurevLan/NetLanVentory) | Large FastAPI vulnerability/compliance platform with dark dashboard. | Preserve Lantern's smaller companion-tool scope; borrow visual polish, not complexity. |
| [`koderas/net-sentinel`](https://github.com/koderas/net-sentinel) | Home network monitoring with SQLite and AI briefings. | Future scheduled diff summaries would fit Lantern well. |

## Differentiation

Lantern should not compete as “yet another scanner.” Its sharper niche is:

1. Ingest evidence from Nmap, ARP, Windows neighbor cache, and router exports.
2. Preserve identity continuity by MAC, including WSL/IP-only scan merge behavior.
3. Baseline known-good state and report meaningful deltas.
4. Prioritize obvious home-network risks in language a household admin can act on.
5. Produce reports that look good enough to share but remain plain-file and portable.

## Near-term improvements worth doing

- HTML report renderer with polished visual risk cards. **Done.**
- GitHub-facing README polish with badges and clearer positioning. **Done.**
- GitHub Actions CI. **Done.**
- Device labels/owners/notes.
- JSON and CSV report exports.
- OUI vendor enrichment.
- Optional lightweight dashboard/search UI.
- Scheduled scan/diff alerting.
