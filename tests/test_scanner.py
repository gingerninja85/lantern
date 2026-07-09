from click.testing import CliRunner

from lantern.cli import main
from lantern.inventory import Observation, Port
from lantern.scanner import PortSpec, observations_from_neighbor_csv, parse_ports, parse_targets, scan_targets


def test_parse_ports_profiles_and_ranges():
    assert 23 in parse_ports("quick")
    assert 32400 in parse_ports("extended")
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_supports_protocols_and_nas_profile():
    ports = parse_ports("nas")
    assert PortSpec("tcp", 445) in ports
    assert PortSpec("tcp", 2049) in ports
    assert PortSpec("udp", 161) in ports
    assert parse_ports("tcp/22,udp/53") == [PortSpec("tcp", 22), PortSpec("udp", 53)]


def test_scan_targets_routes_udp_specs(monkeypatch):
    def fake_scan_port(ip, port, timeout):
        assert ip == "10.0.0.50"
        assert timeout == 0.1
        return Port(protocol=port.protocol, number=port.number, service="domain")

    monkeypatch.setattr("lantern.scanner.scan_port", fake_scan_port)
    scanned = scan_targets([Observation(ip="10.0.0.50")], [PortSpec("udp", 53)], timeout=0.1)
    assert scanned[0].ports == [Port(protocol="udp", number=53, service="domain")]


def test_parse_targets_cidr_guard():
    assert parse_targets(targets="192.168.1.2,192.168.1.1") == ["192.168.1.1", "192.168.1.2"]
    assert parse_targets(cidr="192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_windows_neighbor_csv_to_observations():
    csv_text = '"IPAddress","LinkLayerAddress","State","InterfaceAlias"\n"10.0.0.12","AA-BB-CC-00-11-22","Reachable","Wi-Fi"\n'
    observations = observations_from_neighbor_csv(csv_text)
    assert observations == [Observation(ip="10.0.0.12", mac="AA:BB:CC:00:11:22", vendor="Wi-Fi")]


def test_scan_command_records_observations_and_writes_report(tmp_path, monkeypatch):
    def fake_scan_lan(*args, **kwargs):
        return [
            Observation(
                ip="10.0.0.55",
                mac="AA:BB:CC:DD:EE:55",
                hostname="camera",
                vendor="Lab",
                ports=[Port(protocol="tcp", number=23, service="telnet", product="BusyBox")],
            )
        ], type("Summary", (), {"targets": 1, "devices_seen": 1, "open_ports": 1})()

    monkeypatch.setattr("lantern.cli.scan_lan", fake_scan_lan)
    db_path = tmp_path / "lantern.sqlite"
    report_path = tmp_path / "report.html"
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            "--db",
            str(db_path),
            "scan",
            "--no-neighbors",
            "--targets",
            "10.0.0.55",
            "--ports",
            "23",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "scanned_targets=1" in result.output
    assert report_path.exists()
    assert "Telnet exposed" in report_path.read_text()

    export = runner.invoke(main, ["--db", str(db_path), "export", "--format", "json"])
    assert export.exit_code == 0
    assert "10.0.0.55" in export.output
