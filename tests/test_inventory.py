from pathlib import Path

from lantern.inventory import Inventory, Observation, Port
from lantern.risk import score_observation
from lantern.report import render_markdown_report


NMAP_XML = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.20" addrtype="ipv4" />
    <address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="CameraCorp" />
    <hostnames><hostname name="ipc-cam" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open" />
        <service name="telnet" product="BusyBox telnetd" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="Boa" version="0.94" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_import_nmap_xml_tracks_device_by_mac_and_ports(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")

    result = inventory.ingest_nmap_xml(NMAP_XML, source="unit-test")

    assert result.devices_seen == 1
    device = inventory.get_device("AA:BB:CC:00:11:22")
    assert device is not None
    assert device.ip == "192.168.1.20"
    assert device.hostname == "ipc-cam"
    assert device.vendor == "CameraCorp"
    assert {port.number for port in device.ports} == {23, 80}


def test_diff_flags_new_device_and_new_port(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")
    inventory.record_observation(
        Observation(
            ip="192.168.1.20",
            mac="AA:BB:CC:00:11:22",
            hostname="ipc-cam",
            vendor="CameraCorp",
            ports=[Port(protocol="tcp", number=80, service="http", product="Boa")],
        )
    )
    inventory.mark_baseline("before")

    inventory.ingest_nmap_xml(NMAP_XML, source="after")
    diff = inventory.diff_against_baseline("before")

    assert diff.new_devices == []
    assert diff.new_ports[0].device_key == "AA:BB:CC:00:11:22"
    assert diff.new_ports[0].port.number == 23
    assert diff.new_ports[0].port.service == "telnet"


def test_risk_score_flags_telnet_and_embedded_http():
    observation = Observation(
        ip="192.168.1.20",
        mac="AA:BB:CC:00:11:22",
        hostname="ipc-cam",
        vendor="CameraCorp",
        ports=[
            Port(protocol="tcp", number=23, service="telnet", product="BusyBox telnetd"),
            Port(protocol="tcp", number=80, service="http", product="Boa", version="0.94"),
        ],
    )

    risk = score_observation(observation)

    assert risk.level == "high"
    assert "Telnet exposed" in risk.findings
    assert "Embedded/admin HTTP service exposed" in risk.findings


def test_markdown_report_contains_diff_and_recommendations(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")
    inventory.record_observation(
        Observation(
            ip="192.168.1.20",
            mac="AA:BB:CC:00:11:22",
            hostname="ipc-cam",
            vendor="CameraCorp",
            ports=[Port(protocol="tcp", number=80, service="http", product="Boa")],
        )
    )
    inventory.mark_baseline("before")
    inventory.ingest_nmap_xml(NMAP_XML, source="after")

    report = render_markdown_report(inventory, baseline="before")

    assert "# Lantern LAN Report" in report
    assert "New ports" in report
    assert "tcp/23 telnet" in report
    assert "Move unknown or risky IoT devices to a guest/IoT VLAN" in report
