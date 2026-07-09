from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import io
import platform
import socket
import subprocess
from typing import Iterable

from lantern.inventory import Observation, Port, normalize_mac


@dataclass(frozen=True)
class PortSpec:
    protocol: str
    number: int

    @property
    def label(self) -> str:
        return f"{self.protocol}/{self.number}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.protocol == "tcp" and self.number == other
        if isinstance(other, PortSpec):
            return (self.protocol, self.number) == (other.protocol, other.number)
        return False

    def __hash__(self) -> int:
        return hash((self.protocol, self.number))


QUICK_PORTS = [
    PortSpec("tcp", port)
    for port in [
        21,
        22,
        23,
        53,
        80,
        81,
        135,
        139,
        443,
        445,
        548,
        554,
        800,
        8000,
        8001,
        8080,
        8443,
        2049,
        3389,
        5000,
        5001,
        5006,
        5357,
        7547,
        8096,
        8920,
        9100,
        32400,
    ]
] + [PortSpec("udp", port) for port in [53, 123, 161, 162, 500, 1194, 1900]]

EXTENDED_PORTS = sorted(
    set(
        QUICK_PORTS
        + [
            PortSpec("tcp", port)
            for port in [
                25,
                110,
                143,
                389,
                515,
                631,
                993,
                995,
                1723,
                1883,
                3306,
                5432,
                5900,
                6379,
                7000,
                8090,
                8888,
                9000,
                9090,
                10000,
            ]
        ]
        + [PortSpec("udp", port) for port in [67, 68, 137, 138, 5353, 5355]]
    ),
    key=lambda port: (port.protocol, port.number),
)

SERVICE_NAMES = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 25): "smtp",
    ("tcp", 53): "domain",
    ("udp", 53): "domain",
    ("tcp", 80): "http",
    ("tcp", 81): "http-alt",
    ("tcp", 110): "pop3",
    ("udp", 123): "ntp",
    ("tcp", 135): "msrpc",
    ("udp", 137): "netbios-ns",
    ("udp", 138): "netbios-dgm",
    ("tcp", 139): "netbios-ssn",
    ("tcp", 143): "imap",
    ("udp", 161): "snmp",
    ("udp", 162): "snmptrap",
    ("tcp", 389): "ldap",
    ("tcp", 443): "https",
    ("tcp", 445): "microsoft-ds",
    ("udp", 500): "isakmp",
    ("tcp", 515): "printer",
    ("tcp", 548): "afp",
    ("tcp", 554): "rtsp",
    ("tcp", 631): "ipp",
    ("udp", 1194): "openvpn",
    ("tcp", 1723): "pptp",
    ("tcp", 1883): "mqtt",
    ("udp", 1900): "upnp",
    ("tcp", 2049): "nfs",
    ("tcp", 3306): "mysql",
    ("tcp", 3389): "ms-wbt-server",
    ("tcp", 5000): "http-alt",
    ("tcp", 5001): "https-alt",
    ("tcp", 5006): "http-alt",
    ("udp", 5353): "mdns",
    ("udp", 5355): "llmnr",
    ("tcp", 5357): "wsdapi",
    ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc",
    ("tcp", 6379): "redis",
    ("tcp", 7547): "cwmp",
    ("tcp", 8000): "http-alt",
    ("tcp", 8001): "http-alt",
    ("tcp", 8080): "http-proxy",
    ("tcp", 8090): "http-alt",
    ("tcp", 8096): "jellyfin",
    ("tcp", 8443): "https-alt",
    ("tcp", 8888): "http-alt",
    ("tcp", 8920): "jellyfin-https",
    ("tcp", 9000): "http-alt",
    ("tcp", 9090): "http-alt",
    ("tcp", 9100): "jetdirect",
    ("tcp", 10000): "webmin",
    ("tcp", 32400): "plex",
}

UDP_PROBES = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    123: b"\x1b" + (b"\x00" * 47),
    161: b"0&\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x000\x0b0\x09\x06\x05+\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
}


@dataclass(frozen=True)
class ScanSummary:
    targets: int
    devices_seen: int
    open_ports: int


def parse_ports(spec: str | None) -> list[PortSpec]:
    """Parse a profile name or comma/range port specification.

    Bare numbers are treated as TCP for backward compatibility. Use udp/53 or
    tcp/80 to force a protocol. Profiles include both TCP and selected UDP where
    useful; UDP results only count when a service responds, so absence of a UDP
    result does not prove a port is closed.
    """
    if spec is None or spec.strip().lower() in {"quick", "top", "common"}:
        return QUICK_PORTS.copy()
    if spec.strip().lower() in {"extended", "safe"}:
        return EXTENDED_PORTS.copy()
    if spec.strip().lower() in {"nas", "storage"}:
        return [
            PortSpec("tcp", port)
            for port in [21, 22, 80, 443, 445, 548, 2049, 5000, 5001, 5006, 8000, 8001, 8080]
        ] + [PortSpec("udp", port) for port in [53, 123, 161, 162, 1900]]
    if spec.strip().lower() in {"admin", "web"}:
        return [
            PortSpec("tcp", port)
            for port in [80, 443, 800, 5000, 5001, 5006, 8000, 8001, 8080, 8096, 8443, 8920, 10000]
        ]
    if spec.strip().lower() in {"all", "full"}:
        return [PortSpec("tcp", port) for port in range(1, 65536)]

    ports: set[PortSpec] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip().lower()
        if not chunk:
            continue
        protocol = "tcp"
        if "/" in chunk:
            protocol, chunk = chunk.split("/", 1)
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"invalid protocol: {protocol}")
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.update(PortSpec(protocol, port) for port in range(int(start), int(end) + 1))
        else:
            ports.add(PortSpec(protocol, int(chunk)))
    invalid = [port for port in ports if port.number < 1 or port.number > 65535]
    if invalid:
        raise ValueError(f"invalid ports: {[port.label for port in invalid[:5]]}")
    return sorted(ports, key=lambda port: (port.protocol, port.number))


def parse_targets(targets: str | None = None, cidr: str | None = None, max_hosts: int = 1024) -> list[str]:
    ips: list[str] = []
    if targets:
        for item in targets.replace("\n", ",").split(","):
            item = item.strip()
            if item:
                ips.append(str(ipaddress.ip_address(item)))
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > max_hosts:
            raise ValueError(f"CIDR has {len(hosts)} hosts; refusing above max_hosts={max_hosts}")
        ips.extend(str(ip) for ip in hosts)
    return sorted(set(ips), key=lambda ip: tuple(int(part) for part in ip.split(".")))


def discover_neighbors() -> list[Observation]:
    if platform.system().lower() == "windows":
        return discover_windows_neighbors()
    return discover_linux_neighbors()


def discover_windows_neighbors() -> list[Observation]:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "Get-NetNeighbor -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.State -ne 'Unreachable' } | "
        "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | ConvertTo-Csv -NoTypeInformation",
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    return observations_from_neighbor_csv(completed.stdout)


def discover_linux_neighbors() -> list[Observation]:
    completed = subprocess.run(["ip", "-4", "neigh", "show"], check=False, capture_output=True, text=True, timeout=15)
    observations: list[Observation] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1]
        if mac and mac != "00:00:00:00:00:00":
            observations.append(Observation(ip=ip, mac=normalize_mac(mac)))
    return observations


def observations_from_neighbor_csv(csv_text: str) -> list[Observation]:
    reader = csv.DictReader(io.StringIO(csv_text))
    observations: list[Observation] = []
    for row in reader:
        ip = (row.get("IPAddress") or row.get("IP address") or row.get("ip") or "").strip()
        mac = (row.get("LinkLayerAddress") or row.get("Link-layer address") or row.get("mac") or "").strip()
        if not ip or not mac or mac in {"00-00-00-00-00-00", "00:00:00:00:00:00"}:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        observations.append(Observation(ip=ip, mac=normalize_mac(mac), vendor=(row.get("InterfaceAlias") or "").strip() or None))
    return observations


def scan_lan(
    targets: Iterable[str] | None = None,
    ports: Iterable[PortSpec | int] | None = None,
    timeout: float = 0.45,
    workers: int = 128,
    include_neighbors: bool = True,
) -> tuple[list[Observation], ScanSummary]:
    base: dict[str, Observation] = {}
    if include_neighbors:
        for obs in discover_neighbors():
            base[obs.ip] = obs
    if targets:
        for ip in targets:
            base.setdefault(str(ip), Observation(ip=str(ip)))
    scan_ports = list(ports or QUICK_PORTS)
    scanned = scan_targets(base.values(), scan_ports, timeout=timeout, workers=workers)
    observations = sorted(scanned, key=lambda obs: tuple(int(part) for part in obs.ip.split(".")))
    summary = ScanSummary(
        targets=len(observations),
        devices_seen=len(observations),
        open_ports=sum(len(obs.ports) for obs in observations),
    )
    return observations, summary


def scan_targets(
    observations: Iterable[Observation],
    ports: Iterable[PortSpec | int],
    timeout: float = 0.45,
    workers: int = 128,
) -> list[Observation]:
    obs_by_ip = {obs.ip: obs for obs in observations}
    port_list = [_coerce_port_spec(port) for port in ports]
    found: dict[str, list[Port]] = {ip: [] for ip in obs_by_ip}
    jobs = [(ip, port) for ip in obs_by_ip for port in port_list]
    if not jobs:
        return list(obs_by_ip.values())
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        future_map = {pool.submit(scan_port, ip, port, timeout): (ip, port) for ip, port in jobs}
        for future in as_completed(future_map):
            ip, _port = future_map[future]
            port = future.result()
            if port is not None:
                found[ip].append(port)
    out: list[Observation] = []
    for ip, obs in obs_by_ip.items():
        out.append(
            Observation(
                ip=obs.ip,
                mac=obs.mac,
                hostname=obs.hostname,
                vendor=obs.vendor,
                ports=sorted(found[ip], key=lambda port: (port.protocol, port.number)),
            )
        )
    return out


def _coerce_port_spec(port: PortSpec | int) -> PortSpec:
    if isinstance(port, PortSpec):
        return port
    return PortSpec("tcp", int(port))


def scan_port(ip: str, port: PortSpec, timeout: float) -> Port | None:
    if port.protocol == "udp":
        return scan_udp_port(ip, port.number, timeout)
    return scan_tcp_port(ip, port.number, timeout)


def scan_tcp_port(ip: str, port: int, timeout: float) -> Port | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return Port(protocol="tcp", number=port, service=SERVICE_NAMES.get(("tcp", port), ""))
    except OSError:
        return None


def scan_udp_port(ip: str, port: int, timeout: float) -> Port | None:
    """Best-effort UDP probe.

    UDP is intentionally conservative: only record a port when a service sends a
    response. No response can mean open, filtered, or closed-by-firewall.
    """
    payload = UDP_PROBES.get(port, b"")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            sock.recvfrom(4096)
            return Port(protocol="udp", number=port, service=SERVICE_NAMES.get(("udp", port), ""))
    except OSError:
        return None


def observations_to_csv(observations: Iterable[Observation]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ip", "mac", "hostname", "vendor", "label", "owner", "notes", "ports"])
    for obs in observations:
        writer.writerow([
            obs.ip,
            obs.mac or "",
            obs.hostname or "",
            obs.vendor or "",
            obs.label or "",
            obs.owner or "",
            obs.notes or "",
            ";".join(port.label for port in obs.ports),
        ])
    return out.getvalue()
