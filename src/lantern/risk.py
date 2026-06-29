from __future__ import annotations

from dataclasses import dataclass

from lantern.inventory import Observation


@dataclass(frozen=True)
class Risk:
    level: str
    score: int
    findings: list[str]


RISKY_PORTS = {
    23: "Telnet exposed",
    445: "SMB exposed",
    139: "NetBIOS exposed",
    1900: "UPnP exposed",
    7547: "CPE WAN management exposed",
}

HTTP_ADMIN_HINTS = ("boa", "goahead", "lighttpd", "busybox", "mini_httpd", "webcam", "ip camera")


def score_observation(observation: Observation) -> Risk:
    findings: list[str] = []
    score = 0
    for port in observation.ports:
        if port.number in RISKY_PORTS:
            findings.append(RISKY_PORTS[port.number])
            score += 40 if port.number == 23 else 25

        service_blob = " ".join([port.service, port.product, port.version]).lower()
        if port.service in {"http", "https"} and any(hint in service_blob for hint in HTTP_ADMIN_HINTS):
            findings.append("Embedded/admin HTTP service exposed")
            score += 25

    if not observation.mac:
        findings.append("No MAC address captured; identity continuity is weak")
        score += 10

    if score >= 60:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "info"
    return Risk(level=level, score=score, findings=sorted(set(findings)))
