# Target validation module
# Checks format, resolves hostnames, and verifies reachability.

import socket
import subprocess
import platform
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass

from .utils import (
    is_valid_domain, is_valid_ip, resolve_target,
    get_all_ips_for_domain, Evidence, EvidenceType
)


@dataclass
class ValidationResult:
    is_valid: bool
    is_reachable: bool
    target_ip: Optional[str]
    target_type: Optional[str]  # "ip" or "domain"
    original_target: str
    all_resolved_ips: List[str]
    error_message: Optional[str] = None
    evidence: List[Evidence] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


class TargetValidator:
    # Validates targets and checks reachability via ICMP/TCP.

    PROBE_PORTS = [80, 443, 22, 21, 25, 8080, 8443]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def validate(self, target: str) -> ValidationResult:
        target = target.strip().lower()

        if not self._validate_format(target):
            return ValidationResult(
                is_valid=False,
                is_reachable=False,
                target_ip=None,
                target_type=None,
                original_target=target,
                all_resolved_ips=[],
                error_message="Invalid target format. Expected domain or IP address."
            )

        resolved_ip, target_type = resolve_target(target)
        if not resolved_ip:
            return ValidationResult(
                is_valid=True,
                is_reachable=False,
                target_ip=None,
                target_type=target_type,
                original_target=target,
                all_resolved_ips=[],
                error_message="Failed to resolve hostname to IP address."
            )

        all_ips = []
        if target_type == "domain":
            all_ips = get_all_ips_for_domain(target)
        else:
            all_ips = [resolved_ip]

        is_reachable, evidence = self._check_reachability(resolved_ip)

        if not is_reachable:
            return ValidationResult(
                is_valid=True,
                is_reachable=False,
                target_ip=resolved_ip,
                target_type=target_type,
                original_target=target,
                all_resolved_ips=all_ips,
                error_message="Target is not reachable via ICMP or common TCP ports.",
                evidence=evidence
            )

        return ValidationResult(
            is_valid=True,
            is_reachable=True,
            target_ip=resolved_ip,
            target_type=target_type,
            original_target=target,
            all_resolved_ips=all_ips,
            evidence=evidence
        )

    def _validate_format(self, target: str) -> bool:
        return is_valid_domain(target) or is_valid_ip(target)

    def _check_reachability(self, ip: str) -> Tuple[bool, List[Evidence]]:
        evidence = []

        icmp_reachable = self._icmp_ping(ip)
        if icmp_reachable:
            evidence.append(Evidence(
                source="ICMP Ping",
                finding=f"Host {ip} responds to ICMP echo requests",
                evidence_type=EvidenceType.CONFIRMED
            ))
            return True, evidence

        evidence.append(Evidence(
            source="ICMP Ping",
            finding=f"Host {ip} does not respond to ICMP (may be filtered)",
            evidence_type=EvidenceType.WEAK
        ))

        for port in self.PROBE_PORTS:
            if self._tcp_probe(ip, port):
                evidence.append(Evidence(
                    source="TCP Probe",
                    finding=f"Host {ip} responds on TCP port {port}",
                    evidence_type=EvidenceType.CONFIRMED
                ))
                return True, evidence

        return False, evidence

    def _icmp_ping(self, ip: str) -> bool:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"

        try:
            result = subprocess.run(
                ["ping", param, "1", timeout_param, str(int(self.timeout * 1000 if platform.system().lower() == "windows" else self.timeout)), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    def _tcp_probe(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except (socket.error, socket.timeout):
            return False

    def get_target_info(self, target: str) -> Dict:
        result = self.validate(target)
        return {
            "original_target": result.original_target,
            "target_type": result.target_type,
            "primary_ip": result.target_ip,
            "all_ips": result.all_resolved_ips,
            "is_valid": result.is_valid,
            "is_reachable": result.is_reachable,
            "error": result.error_message,
            "evidence": [e.to_dict() for e in result.evidence]
        }
