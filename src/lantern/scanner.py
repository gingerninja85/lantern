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

QUICK_PORTS = [22, 23, 53, 80, 81, 135, 139, 443, 445, 554, 8000, 8080, 8443, 1900, 3389, 5000, 5001, 5357, 7547, 9100]
EXTENDED_PORTS = sorted(set(QUICK_PORTS + [21, 25, 110, 143, 161, 389, 515, 631, 993, 995, 1723, 1883, 3306, 5432, 5900, 6379, 7000, 8090, 8888, 9000, 9090, 10000, 32400]))

SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    81: "http-alt",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    515: "printer",
    554: "rtsp",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    1883: "mqtt",
    1900: "upnp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http-alt",
    5001: "http-alt",
    5357: "wsdapi",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    7547: "cwmp",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-alt",
    9100: "jetdirect",
    10000: "webmin",
    32400: "plex",
}

@dataclass(frozen=True)
class ScanSummary:
    targets: int
    devices_seen: int
    open_ports: int


def parse_ports(spec: str | None) -> list[int]:
    """Parse a profile name or comma/range TCP port specification."""
    if spec is None or spec.strip().lower() in {"quick", "top", "common"}:
        return QUICK_PORTS.copy()
    if spec.strip().lower() in {"extended", "safe"}:
        return EXTENDED_PORTS.copy()
    if spec.strip().lower() in {"all", "full"}:
        return list(range(1, 65536))

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"invalid TCP ports: {invalid[:5]}")
    return sorted(ports)


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
    ports: Iterable[int] | None = None,
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
    ports: Iterable[int],
    timeout: float = 0.45,
    workers: int = 128,
) -> list[Observation]:
    obs_by_ip = {obs.ip: obs for obs in observations}
    port_list = list(ports)
    found: dict[str, list[Port]] = {ip: [] for ip in obs_by_ip}
    jobs = [(ip, port) for ip in obs_by_ip for port in port_list]
    if not jobs:
        return list(obs_by_ip.values())
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        future_map = {pool.submit(scan_tcp_port, ip, port, timeout): (ip, port) for ip, port in jobs}
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
                ports=sorted(found[ip], key=lambda port: port.number),
            )
        )
    return out


def scan_tcp_port(ip: str, port: int, timeout: float) -> Port | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            product = probe_banner(sock, port)
            return Port(protocol="tcp", number=port, service=SERVICE_NAMES.get(port, "unknown"), product=product)
    except OSError:
        return None


def probe_banner(sock: socket.socket, port: int) -> str:
    try:
        if port in {80, 81, 8000, 8080, 8888, 9000, 9090, 10000}:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in {443, 8443}:
            return "TLS service"
        data = sock.recv(512)
        text = data.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ").strip()
        return text[:160]
    except OSError:
        return ""


def observations_to_csv(observations: Iterable[Observation]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ip", "mac", "hostname", "vendor", "ports"])
    for obs in observations:
        writer.writerow([
            obs.ip,
            obs.mac or "",
            obs.hostname or "",
            obs.vendor or "",
            ";".join(str(port.number) for port in obs.ports),
        ])
    return buffer.getvalue()
