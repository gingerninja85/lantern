from __future__ import annotations

import csv
from dataclasses import dataclass, field
import io
from pathlib import Path
import sqlite3
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class Port:
    protocol: str
    number: int
    service: str = ""
    product: str = ""
    version: str = ""

    @property
    def label(self) -> str:
        service = f" {self.service}" if self.service else ""
        return f"{self.protocol}/{self.number}{service}"


@dataclass
class Observation:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    ports: list[Port] = field(default_factory=list)

    @property
    def key(self) -> str:
        normalized = normalize_mac(self.mac)
        return normalized if normalized else self.ip


@dataclass(frozen=True)
class IngestResult:
    devices_seen: int
    ports_seen: int


@dataclass(frozen=True)
class PortChange:
    device_key: str
    ip: str
    hostname: str | None
    port: Port


@dataclass(frozen=True)
class InventoryDiff:
    new_devices: list[Observation]
    new_ports: list[PortChange]


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.strip().replace("-", ":").upper()
    if len(cleaned) == 12 and ":" not in cleaned:
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def _first_present(row: dict[str, str], names: tuple[str, ...]) -> str | None:
    lowered = {key.strip().lower(): value.strip() for key, value in row.items() if key is not None}
    for name in names:
        value = lowered.get(name)
        if value:
            return value
    return None


class Inventory:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_key TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_seen TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS ports (
                    device_key TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    number INTEGER NOT NULL,
                    service TEXT DEFAULT '',
                    product TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (device_key, protocol, number)
                );
                CREATE TABLE IF NOT EXISTS baselines (
                    name TEXT PRIMARY KEY,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS baseline_devices (
                    baseline TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    PRIMARY KEY (baseline, device_key)
                );
                CREATE TABLE IF NOT EXISTS baseline_ports (
                    baseline TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    number INTEGER NOT NULL,
                    service TEXT DEFAULT '',
                    product TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    PRIMARY KEY (baseline, device_key, protocol, number)
                );
                """
            )

    def record_observation(self, observation: Observation) -> None:
        key = observation.key
        mac = normalize_mac(observation.mac)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices(device_key, ip, mac, hostname, vendor)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_key) DO UPDATE SET
                    ip = excluded.ip,
                    mac = COALESCE(excluded.mac, devices.mac),
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    last_seen = CURRENT_TIMESTAMP
                """,
                (key, observation.ip, mac, observation.hostname, observation.vendor),
            )
            for port in observation.ports:
                conn.execute(
                    """
                    INSERT INTO ports(device_key, protocol, number, service, product, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(device_key, protocol, number) DO UPDATE SET
                        service = excluded.service,
                        product = excluded.product,
                        version = excluded.version,
                        last_seen = CURRENT_TIMESTAMP
                    """,
                    (key, port.protocol, port.number, port.service, port.product, port.version),
                )

    def ingest_nmap_xml(self, xml_text: str, source: str = "nmap") -> IngestResult:
        del source  # reserved for the evidence log planned after MVP
        root = ET.fromstring(xml_text)
        devices = 0
        ports = 0
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.attrib.get("state") != "up":
                continue

            ip = None
            mac = None
            vendor = None
            for address in host.findall("address"):
                addrtype = address.attrib.get("addrtype")
                if addrtype == "ipv4":
                    ip = address.attrib.get("addr")
                elif addrtype == "mac":
                    mac = address.attrib.get("addr")
                    vendor = address.attrib.get("vendor")
            if not ip:
                continue

            hostname = None
            hostname_node = host.find("hostnames/hostname")
            if hostname_node is not None:
                hostname = hostname_node.attrib.get("name")

            parsed_ports: list[Port] = []
            for port_node in host.findall("ports/port"):
                state = port_node.find("state")
                if state is not None and state.attrib.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                parsed_ports.append(
                    Port(
                        protocol=port_node.attrib.get("protocol", "tcp"),
                        number=int(port_node.attrib["portid"]),
                        service=(service_node.attrib.get("name", "") if service_node is not None else ""),
                        product=(service_node.attrib.get("product", "") if service_node is not None else ""),
                        version=(service_node.attrib.get("version", "") if service_node is not None else ""),
                    )
                )
            self.record_observation(
                Observation(ip=ip, mac=mac, hostname=hostname, vendor=vendor, ports=parsed_ports)
            )
            devices += 1
            ports += len(parsed_ports)
        return IngestResult(devices_seen=devices, ports_seen=ports)

    def ingest_arp_csv(self, csv_text: str, source: str = "arp-csv") -> IngestResult:
        del source  # reserved for the evidence log planned after MVP
        devices = 0
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            ip = _first_present(row, ("ip", "ipaddress", "ip address", "address", "internet address"))
            mac = _first_present(
                row,
                (
                    "mac",
                    "macaddress",
                    "mac address",
                    "physical address",
                    "link-layer address",
                    "linklayeraddress",
                ),
            )
            if not ip:
                continue
            hostname = _first_present(row, ("hostname", "host", "name", "dns", "device", "comment"))
            vendor = _first_present(row, ("vendor", "manufacturer", "oui"))
            self.record_observation(
                Observation(ip=ip, mac=normalize_mac(mac), hostname=hostname, vendor=vendor, ports=[])
            )
            devices += 1
        return IngestResult(devices_seen=devices, ports_seen=0)

    def get_device(self, key: str) -> Observation | None:
        key = normalize_mac(key) or key
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE device_key = ?", (key,)).fetchone()
            if row is None:
                return None
            ports = [
                Port(
                    protocol=p["protocol"],
                    number=p["number"],
                    service=p["service"] or "",
                    product=p["product"] or "",
                    version=p["version"] or "",
                )
                for p in conn.execute(
                    "SELECT * FROM ports WHERE device_key = ? ORDER BY protocol, number", (key,)
                )
            ]
        return Observation(
            ip=row["ip"], mac=row["mac"], hostname=row["hostname"], vendor=row["vendor"], ports=ports
        )

    def list_devices(self) -> list[Observation]:
        with self._connect() as conn:
            keys = [r["device_key"] for r in conn.execute("SELECT device_key FROM devices ORDER BY ip")]
        return [device for key in keys if (device := self.get_device(key)) is not None]

    def mark_baseline(self, name: str) -> None:
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO baselines(name) VALUES (?)", (name,))
            conn.execute("DELETE FROM baseline_devices WHERE baseline = ?", (name,))
            conn.execute("DELETE FROM baseline_ports WHERE baseline = ?", (name,))
            conn.execute(
                """
                INSERT INTO baseline_devices(baseline, device_key, ip, mac, hostname, vendor)
                SELECT ?, device_key, ip, mac, hostname, vendor FROM devices
                """,
                (name,),
            )
            conn.execute(
                """
                INSERT INTO baseline_ports(baseline, device_key, protocol, number, service, product, version)
                SELECT ?, device_key, protocol, number, service, product, version FROM ports
                """,
                (name,),
            )

    def diff_against_baseline(self, name: str) -> InventoryDiff:
        with self._connect() as conn:
            new_device_rows = conn.execute(
                """
                SELECT d.* FROM devices d
                LEFT JOIN baseline_devices b ON b.baseline = ? AND b.device_key = d.device_key
                WHERE b.device_key IS NULL
                ORDER BY d.ip
                """,
                (name,),
            ).fetchall()
            new_port_rows = conn.execute(
                """
                SELECT d.device_key, d.ip, d.hostname, p.protocol, p.number, p.service, p.product, p.version
                FROM ports p
                JOIN devices d ON d.device_key = p.device_key
                LEFT JOIN baseline_ports b
                  ON b.baseline = ?
                 AND b.device_key = p.device_key
                 AND b.protocol = p.protocol
                 AND b.number = p.number
                WHERE b.device_key IS NULL
                ORDER BY d.ip, p.protocol, p.number
                """,
                (name,),
            ).fetchall()

        new_devices: list[Observation] = []
        for row in new_device_rows:
            device = self.get_device(row["device_key"])
            if device is not None:
                new_devices.append(device)
        new_ports = [
            PortChange(
                device_key=row["device_key"],
                ip=row["ip"],
                hostname=row["hostname"],
                port=Port(
                    protocol=row["protocol"],
                    number=row["number"],
                    service=row["service"] or "",
                    product=row["product"] or "",
                    version=row["version"] or "",
                ),
            )
            for row in new_port_rows
        ]
        return InventoryDiff(new_devices=new_devices, new_ports=new_ports)
