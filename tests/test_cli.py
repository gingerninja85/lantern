from click.testing import CliRunner

from lantern.cli import main


NMAP_XML = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.30" addrtype="ipv4" />
    <address addr="DE:AD:BE:EF:00:01" addrtype="mac" vendor="UnknownIoT" />
    <ports>
      <port protocol="tcp" portid="1900">
        <state state="open" />
        <service name="upnp" product="MiniUPnPd" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_cli_ingest_and_report(tmp_path):
    xml_path = tmp_path / "scan.xml"
    db_path = tmp_path / "lantern.sqlite"
    xml_path.write_text(NMAP_XML)

    runner = CliRunner()
    ingest = runner.invoke(main, ["--db", str(db_path), "ingest-nmap", str(xml_path)])
    assert ingest.exit_code == 0
    assert "devices_seen=1" in ingest.output

    report = runner.invoke(main, ["--db", str(db_path), "report"])
    assert report.exit_code == 0
    assert "192.168.1.30" in report.output
    assert "UPnP exposed" in report.output


def test_cli_ingest_arp_and_diff_report(tmp_path):
    csv_path = tmp_path / "arp.csv"
    db_path = tmp_path / "lantern.sqlite"
    csv_path.write_text(
        "ip,mac,hostname,vendor\n"
        "192.168.1.10,AA:AA:AA:AA:AA:AA,laptop,Apple\n"
    )

    runner = CliRunner()
    ingest = runner.invoke(main, ["--db", str(db_path), "ingest-arp", str(csv_path)])
    assert ingest.exit_code == 0
    assert "devices_seen=1" in ingest.output

    baseline = runner.invoke(main, ["--db", str(db_path), "baseline", "known"])
    assert baseline.exit_code == 0

    csv_path.write_text(
        "ip,mac,hostname,vendor\n"
        "192.168.1.10,AA:AA:AA:AA:AA:AA,laptop,Apple\n"
        "192.168.1.88,CC-CC-CC-CC-CC-CC,unknown-device,\n"
    )
    ingest = runner.invoke(main, ["--db", str(db_path), "ingest-arp", str(csv_path)])
    assert ingest.exit_code == 0

    report = runner.invoke(main, ["--db", str(db_path), "report", "--baseline", "known"])
    assert report.exit_code == 0
    assert "New devices" in report.output
    assert "192.168.1.88" in report.output
    assert "CC:CC:CC:CC:CC:CC" in report.output
