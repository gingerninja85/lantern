from click.testing import CliRunner

from lantern.cli import main
from lantern.inventory import Observation, Port
from lantern.scanner import observations_from_neighbor_csv, parse_ports, parse_targets


def test_parse_ports_profiles_and_ranges():
    assert 23 in parse_ports("quick")
    assert 32400 in parse_ports("extended")
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


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
