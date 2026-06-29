from pathlib import Path

from lantern.inventory import Inventory, Observation, Port
from lantern.risk import score_observation
from lantern.report import render_html_report, render_markdown_report


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


def test_import_arp_csv_tracks_devices_without_ports(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")

    result = inventory.ingest_arp_csv(
        "ip,mac,hostname,vendor\n"
        "192.168.1.44,00-11-22-aa-bb-cc,smart-plug,Espressif\n",
        source="router-export",
    )

    assert result.devices_seen == 1
    assert result.ports_seen == 0
    device = inventory.get_device("00:11:22:AA:BB:CC")
    assert device is not None
    assert device.ip == "192.168.1.44"
    assert device.hostname == "smart-plug"
    assert device.vendor == "Espressif"
    assert device.ports == []


def test_arp_csv_diff_flags_new_mac_even_without_ports(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")
    inventory.ingest_arp_csv(
        "ip,mac,hostname,vendor\n192.168.1.10,AA:AA:AA:AA:AA:AA,laptop,Apple\n"
    )
    inventory.mark_baseline("before")

    inventory.ingest_arp_csv(
        "ip,mac,hostname,vendor\n"
        "192.168.1.10,AA:AA:AA:AA:AA:AA,laptop,Apple\n"
        "192.168.1.55,BB-BB-BB-BB-BB-BB,unknown,\n"
    )
    diff = inventory.diff_against_baseline("before")

    assert len(diff.new_devices) == 1
    assert diff.new_devices[0].mac == "BB:BB:BB:BB:BB:BB"
    assert diff.new_devices[0].ip == "192.168.1.55"


def test_arp_csv_accepts_windows_neighbor_export_headers(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")

    result = inventory.ingest_arp_csv(
        "IPAddress,LinkLayerAddress,State,InterfaceAlias\n"
        "192.168.1.77,DD-EE-FF-00-11-22,Reachable,Wi-Fi\n"
    )

    assert result.devices_seen == 1
    device = inventory.get_device("DD:EE:FF:00:11:22")
    assert device is not None
    assert device.ip == "192.168.1.77"


def test_nmap_without_mac_merges_ports_into_existing_ip_device(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")
    inventory.ingest_arp_csv(
        "ip,mac,hostname,vendor\n192.168.1.97,00:11:32:2D:D4:8F,nas,Synology\n"
    )

    inventory.ingest_nmap_xml(
        """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.97" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" product="Samba smbd" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
    )

    assert len(inventory.list_devices()) == 1
    device = inventory.get_device("00:11:32:2D:D4:8F")
    assert device is not None
    assert device.ip == "192.168.1.97"
    assert [port.number for port in device.ports] == [445]


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


def test_risk_score_flags_rdp_and_rtsp_services():
    observation = Observation(
        ip="10.0.0.14",
        mac="AA:BB:CC:DD:EE:FF",
        ports=[
            Port(protocol="tcp", number=3389, service="ms-wbt-server", product="Microsoft Terminal Services"),
            Port(protocol="tcp", number=554, service="rtsp", product="webcam rtspd"),
        ],
    )

    risk = score_observation(observation)

    assert risk.level == "medium"
    assert "RDP exposed" in risk.findings
    assert "RTSP/video stream service exposed" in risk.findings


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
    assert "High risk devices" in report
    assert "New ports" in report
    assert "tcp/23 telnet" in report
    assert "Move unknown or risky IoT devices to a guest/IoT VLAN" in report


def test_html_report_contains_cyberpunk_dashboard_and_escapes_content(tmp_path: Path):
    inventory = Inventory(tmp_path / "lantern.sqlite")
    inventory.record_observation(
        Observation(
            ip="192.168.1.66",
            mac="AA:BB:CC:00:11:66",
            hostname="<script>alert(1)</script>",
            vendor="CameraCorp",
            ports=[
                Port(protocol="tcp", number=23, service="telnet", product="BusyBox telnetd"),
                Port(protocol="tcp", number=80, service="http", product="Boa"),
            ],
        )
    )

    report = render_html_report(inventory)

    assert "<!doctype html>" in report
    assert "Light up" in report
    assert "badge high" in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report
