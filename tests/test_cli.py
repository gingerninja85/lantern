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
