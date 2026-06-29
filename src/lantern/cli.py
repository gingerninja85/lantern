from __future__ import annotations

from pathlib import Path

import click

from lantern.inventory import Inventory
from lantern.report import render_html_report, render_markdown_report


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
