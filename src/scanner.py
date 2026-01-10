# Port discovery module
# TCP connect scan for open port detection.

import socket
import concurrent.futures
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

from .utils import PortInfo, Evidence, EvidenceType


@dataclass
class ScanResult:
    target_ip: str
    open_ports: List[PortInfo]
    closed_ports: List[int]
    filtered_ports: List[int]
    scan_evidence: List[Evidence]


class PortScanner:
    # Minimal TCP connect scanner.

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        8000, 8080, 8443, 8888, 9000, 9090, 9443
    ]

    EXTENDED_PORTS = COMMON_PORTS + [
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        8001, 8002, 8008, 8081, 8082, 8083, 8084, 8085,
        8180, 8181, 8444, 8880, 8881, 9001, 9080, 9443,
        10000, 10443, 4443, 5000, 5001, 7000, 7001, 7443
    ]

    SERVICE_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }

    def __init__(self, timeout: float = 2.0, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(
        self,
        target_ip: str,
        ports: Optional[List[int]] = None,
        extended: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> ScanResult:

        if ports is None:
            ports = self.EXTENDED_PORTS if extended else self.COMMON_PORTS

        ports = list(set(ports))
        open_ports = []
        closed_ports = []
        filtered_ports = []
        evidence = []

        evidence.append(Evidence(
            source="Port Scanner",
            finding=f"Initiating TCP connect scan on {len(ports)} ports",
            evidence_type=EvidenceType.CONFIRMED
        ))

        scanned = 0
        total = len(ports)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._probe_port, target_ip, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                scanned += 1

                if progress_callback:
                    progress_callback(scanned, total)

                try:
                    state, banner = future.result()

                    if state == "open":
                        service = self.SERVICE_PORTS.get(port, self._guess_service(port))
                        port_info = PortInfo(
                            port=port,
                            state="open",
                            service=service,
                            banner=banner
                        )
                        open_ports.append(port_info)

                        evidence.append(Evidence(
                            source="Port Scanner",
                            finding=f"Port {port} is open ({service})",
                            evidence_type=EvidenceType.CONFIRMED,
                            raw_data=banner
                        ))
                    elif state == "closed":
                        closed_ports.append(port)
                    else:
                        filtered_ports.append(port)

                except Exception:
                    filtered_ports.append(port)

        open_ports.sort(key=lambda x: x.port)

        evidence.append(Evidence(
            source="Port Scanner",
            finding=f"Scan complete: {len(open_ports)} open, {len(closed_ports)} closed, {len(filtered_ports)} filtered",
            evidence_type=EvidenceType.CONFIRMED
        ))

        return ScanResult(
            target_ip=target_ip,
            open_ports=open_ports,
            closed_ports=sorted(closed_ports),
            filtered_ports=sorted(filtered_ports),
            scan_evidence=evidence
        )

    def _probe_port(self, ip: str, port: int) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                banner = self._grab_banner(sock, port)
                sock.close()
                return ("open", banner)
            else:
                sock.close()
                if result == 111 or result == 10061:  # ECONNREFUSED
                    return ("closed", None)
                return ("filtered", None)

        except socket.timeout:
            return ("filtered", None)
        except socket.error:
            return ("filtered", None)

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        try:
            sock.settimeout(1.0)

            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443, 9443]:
                return None
            elif port == 22:
                pass
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()[:200]

        except (socket.timeout, socket.error, UnicodeDecodeError):
            return None

    def _guess_service(self, port: int) -> str:
        if port in range(80, 90) or port in [8080, 8000, 8888]:
            return "HTTP"
        if port in range(443, 450) or port in [8443, 9443, 4443]:
            return "HTTPS"
        if port in range(20, 24):
            return "FTP/SSH"
        return "Unknown"

    def quick_scan(self, target_ip: str) -> List[PortInfo]:
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        result = self.scan(target_ip, ports=web_ports)
        return result.open_ports

    def get_http_ports(self, scan_result: ScanResult) -> List[int]:
        http_services = ["HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"]
        return [
            p.port for p in scan_result.open_ports
            if p.service in http_services or p.port in [80, 443, 8080, 8443]
        ]
