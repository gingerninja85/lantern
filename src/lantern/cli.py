from __future__ import annotations

import json
from pathlib import Path

import click

from lantern.inventory import Inventory, Observation
from lantern.report import render_html_report, render_markdown_report
from lantern.scanner import observations_to_csv, parse_ports, parse_targets, scan_lan


@click.group()
@click.option(
    "--db",
    "db_path",
    default="lantern.sqlite",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="SQLite inventory database path.",
)
@click.pass_context
def main(ctx: click.Context, db_path: Path) -> None:
    """LAN inventory, diff, and risk tracker."""
    ctx.obj = {"inventory": Inventory(db_path)}


@main.command("ingest-nmap")
@click.argument("xml_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def ingest_nmap(ctx: click.Context, xml_file: Path) -> None:
    """Ingest an Nmap XML scan."""
    inventory: Inventory = ctx.obj["inventory"]
    result = inventory.ingest_nmap_xml(xml_file.read_text(), source=str(xml_file))
    click.echo(f"devices_seen={result.devices_seen} ports_seen={result.ports_seen}")


@main.command("ingest-arp")
@click.argument("csv_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def ingest_arp(ctx: click.Context, csv_file: Path) -> None:
    """Ingest ARP/router/neighbor CSV with ip, mac, hostname, vendor columns."""
    inventory: Inventory = ctx.obj["inventory"]
    result = inventory.ingest_arp_csv(csv_file.read_text(), source=str(csv_file))
    click.echo(f"devices_seen={result.devices_seen} ports_seen={result.ports_seen}")


@main.command("baseline")
@click.argument("name")
@click.pass_context
def baseline(ctx: click.Context, name: str) -> None:
    """Save the current inventory as a named baseline."""
    inventory: Inventory = ctx.obj["inventory"]
    inventory.mark_baseline(name)
    click.echo(f"baseline={name}")


@main.command("scan")
@click.option(
    "--targets",
    default=None,
    help="Comma/newline separated IPv4 targets. Defaults to Windows neighbor cache / local ARP table.",
)
@click.option("--cidr", default=None, help="Optional IPv4 CIDR to scan, e.g. 10.0.0.0/24.")
@click.option(
    "--ports",
    "port_spec",
    default="quick",
    show_default=True,
    help="Port profile: quick, extended, all, or comma/ranges like 22,80,443,8000-8100.",
)
@click.option("--timeout", default=0.45, show_default=True, type=float, help="TCP connect timeout seconds.")
@click.option("--workers", default=128, show_default=True, type=int, help="Concurrent TCP probes.")
@click.option(
    "--no-neighbors",
    is_flag=True,
    help="Do not include Windows neighbor cache / local ARP table targets.",
)
@click.option("--baseline", "baseline_name", default=None, help="Diff report against a saved baseline.")
@click.option("--save-baseline", default=None, help="Save inventory as this baseline name after scanning.")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["md", "html"]),
    default="html",
    show_default=True,
    help="Report format to emit after scanning.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("lantern-report.html"),
    show_default=True,
    help="Write report to this file. Use '-' for stdout.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    targets: str | None,
    cidr: str | None,
    port_spec: str,
    timeout: float,
    workers: int,
    no_neighbors: bool,
    baseline_name: str | None,
    save_baseline: str | None,
    report_format: str,
    output_path: Path,
) -> None:
    """Discover LAN devices, scan safe TCP ports, store results, and write a report."""
    inventory: Inventory = ctx.obj["inventory"]
    target_list = parse_targets(targets=targets, cidr=cidr)
    port_list = parse_ports(port_spec)
    observations, summary = scan_lan(
        targets=target_list,
        ports=port_list,
        timeout=timeout,
        workers=workers,
        include_neighbors=not no_neighbors,
    )
    for observation in observations:
        inventory.record_observation(observation)

    renderer = render_html_report if report_format == "html" else render_markdown_report
    rendered = renderer(inventory, baseline=baseline_name)
    if save_baseline:
        inventory.mark_baseline(save_baseline)

    click.echo(
        f"scanned_targets={summary.targets} devices_seen={summary.devices_seen} "
        f"open_ports={summary.open_ports} ports_profile={port_spec}"
    )
    if str(output_path) == "-":
        click.echo(rendered, nl=False)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote={output_path}")


@main.command("export")
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    show_default=True,
    help="Export format.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write export to a file instead of stdout.",
)
@click.pass_context
def export_devices(ctx: click.Context, export_format: str, output_path: Path | None) -> None:
    """Export current inventory as JSON or CSV."""
    inventory: Inventory = ctx.obj["inventory"]
    devices = inventory.list_devices()
    if export_format == "csv":
        rendered = observations_to_csv(devices)
    else:
        rendered = json.dumps([_observation_to_dict(device) for device in devices], indent=2) + "\n"
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote={output_path}")
        return
    click.echo(rendered, nl=False)


def _observation_to_dict(observation: Observation) -> dict[str, object]:
    return {
        "ip": observation.ip,
        "mac": observation.mac,
        "hostname": observation.hostname,
        "vendor": observation.vendor,
        "ports": [
            {
                "protocol": port.protocol,
                "number": port.number,
                "service": port.service,
                "product": port.product,
                "version": port.version,
            }
            for port in observation.ports
        ],
    }


@main.command("report")
@click.option("--baseline", "baseline_name", default=None, help="Diff report against a baseline.")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["md", "html"]),
    default="md",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write report to a file instead of stdout.",
)
@click.pass_context
def report(
    ctx: click.Context,
    baseline_name: str | None,
    report_format: str,
    output_path: Path | None,
) -> None:
    """Print or write a LAN report."""
    inventory: Inventory = ctx.obj["inventory"]
    renderer = render_html_report if report_format == "html" else render_markdown_report
    rendered = renderer(inventory, baseline=baseline_name)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote={output_path}")
        return
    click.echo(rendered, nl=False)
