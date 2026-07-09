from __future__ import annotations

from dataclasses import dataclass

from lantern.inventory import Observation


@dataclass(frozen=True)
class RiskFinding:
    title: str
    remediation: str
    score: int


@dataclass(frozen=True)
class Risk:
    level: str
    score: int
    findings: list[str]
    remediations: list[str]


PORT_FINDINGS = {
    ("tcp", 21): RiskFinding(
        "FTP exposed",
        "Disable FTP where possible; prefer SFTP/HTTPS and avoid plaintext credentials.",
        25,
    ),
    ("tcp", 23): RiskFinding(
        "Telnet exposed",
        "Disable Telnet; use SSH or a vendor-managed HTTPS interface instead.",
        45,
    ),
    ("tcp", 139): RiskFinding(
        "NetBIOS exposed",
        "Disable legacy NetBIOS/SMBv1 where possible and restrict file sharing to trusted devices.",
        20,
    ),
    ("tcp", 445): RiskFinding(
        "SMB exposed",
        "Restrict SMB to trusted devices, require modern SMB/authentication, and keep NAS firmware patched.",
        25,
    ),
    ("tcp", 548): RiskFinding(
        "AFP exposed",
        "Disable legacy Apple Filing Protocol unless you still need old macOS clients; prefer SMB with access controls.",
        15,
    ),
    ("tcp", 554): RiskFinding(
        "RTSP/video stream service exposed",
        "Isolate cameras/NVRs on an IoT VLAN and disable unauthenticated RTSP streams.",
        20,
    ),
    ("udp", 161): RiskFinding(
        "SNMP exposed",
        "Disable SNMP or use SNMPv3 with strong credentials; never leave public/private community strings enabled.",
        30,
    ),
    ("udp", 162): RiskFinding(
        "SNMP trap service exposed",
        "Restrict SNMP trap receivers to management hosts only.",
        20,
    ),
    ("udp", 1900): RiskFinding(
        "UPnP exposed",
        "Disable UPnP on routers/NAS devices unless explicitly required; avoid automatic port mappings.",
        25,
    ),
    ("tcp", 1900): RiskFinding(
        "UPnP exposed",
        "Disable UPnP on routers/NAS devices unless explicitly required; avoid automatic port mappings.",
        25,
    ),
    ("tcp", 2049): RiskFinding(
        "NFS exposed",
        "Restrict NFS exports by IP, avoid guest/no_root_squash exports, and keep it off untrusted networks.",
        25,
    ),
    ("tcp", 1883): RiskFinding(
        "MQTT exposed",
        "Require MQTT authentication/TLS or isolate the broker to trusted automation hosts.",
        25,
    ),
    ("tcp", 3306): RiskFinding(
        "MySQL exposed",
        "Bind the database to localhost/private management hosts and require strong credentials.",
        30,
    ),
    ("tcp", 3389): RiskFinding(
        "RDP exposed",
        "Disable RDP if unused; otherwise require VPN/NLA, strong MFA, and restrict source IPs.",
        35,
    ),
    ("tcp", 5432): RiskFinding(
        "PostgreSQL exposed",
        "Bind PostgreSQL to trusted interfaces only and restrict access with firewall rules.",
        30,
    ),
    ("tcp", 5900): RiskFinding(
        "VNC exposed",
        "Disable VNC or require VPN/strong authentication; many VNC deployments are weakly protected.",
        35,
    ),
    ("tcp", 6379): RiskFinding(
        "Redis exposed",
        "Do not expose Redis on a LAN unless required; bind to localhost/trusted hosts and enable authentication.",
        40,
    ),
    ("tcp", 7547): RiskFinding(
        "CPE WAN management exposed",
        "Disable TR-069/CWMP exposure where possible or restrict it to the ISP management path only.",
        45,
    ),
    ("tcp", 9100): RiskFinding(
        "Raw printer port exposed",
        "Restrict JetDirect/raw printing to trusted clients and disable it if IPP/driver-managed printing is available.",
        15,
    ),
    ("tcp", 10000): RiskFinding(
        "Webmin/admin console exposed",
        "Restrict Webmin/admin consoles to a management VLAN or VPN and enforce strong authentication.",
        35,
    ),
}

INFO_PORTS = {
    ("udp", 53): "DNS responder detected",
    ("udp", 123): "NTP responder detected",
    ("udp", 500): "IPsec/IKE VPN endpoint detected",
    ("udp", 1194): "OpenVPN endpoint detected",
    ("tcp", 32400): "Plex media service detected",
}

HTTP_ADMIN_PORTS = {80, 81, 443, 800, 5000, 5001, 5006, 8000, 8001, 8080, 8096, 8443, 8920, 10000}
HTTP_ADMIN_HINTS = (
    "adm",
    "admin",
    "boa",
    "busybox",
    "dsm",
    "goahead",
    "ip camera",
    "lighttpd",
    "mini_httpd",
    "nas",
    "qnap",
    "synology",
    "webcam",
    "webmin",
)


def score_observation(observation: Observation) -> Risk:
    findings: dict[str, str] = {}
    score = 0
    for port in observation.ports:
        key = (port.protocol.lower(), port.number)
        if key in PORT_FINDINGS:
            finding = PORT_FINDINGS[key]
            findings[finding.title] = finding.remediation
            score += finding.score

        if key in INFO_PORTS:
            findings.setdefault(INFO_PORTS[key], "Verify this service is expected on this device.")
            score += 5

        service_blob = " ".join([port.service, port.product, port.version]).lower()
        looks_like_http = port.service in {"http", "https", "http-alt", "https-alt", "http-proxy", "webmin"}
        if port.protocol == "tcp" and port.number in HTTP_ADMIN_PORTS and (
            looks_like_http or any(hint in service_blob for hint in HTTP_ADMIN_HINTS)
        ):
            findings.setdefault(
                "Embedded/admin HTTP service exposed",
                "Confirm the web console needs to be reachable from this LAN; update firmware, use strong credentials, and isolate IoT/NAS admin pages.",
            )
            score += 15

    if not observation.mac:
        findings.setdefault(
            "No MAC address captured; identity continuity is weak",
            "Ingest ARP/router/Windows neighbor evidence so Lantern can track this device by MAC instead of IP only.",
        )
        score += 10

    if score >= 60:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "info"
    return Risk(level=level, score=score, findings=sorted(findings), remediations=[findings[key] for key in sorted(findings)])
