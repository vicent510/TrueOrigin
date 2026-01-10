# TLS and HTTP fingerprinting module
# Analyzes certificates, headers, and response patterns.

import ssl
import socket
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import urllib.request
import urllib.error

from .utils import Evidence, EvidenceType, extract_ip_from_text


@dataclass
class TLSInfo:
    port: int
    has_tls: bool
    certificate: Optional[Dict[str, Any]] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san_domains: List[str] = field(default_factory=list)
    san_ips: List[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class HTTPFingerprint:
    port: int
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    cookies: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


class Fingerprinter:
    # TLS and HTTP fingerprinting for proxy detection.

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def get_tls_info(self, host: str, port: int = 443) -> TLSInfo:
        info = TLSInfo(port=port, has_tls=False)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    info.has_tls = True
                    info.protocol_version = ssock.version()
                    info.cipher_suite = ssock.cipher()[0] if ssock.cipher() else None

                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    if cert:
                        info.fingerprint_sha256 = hashlib.sha256(cert).hexdigest()

                    if cert_dict:
                        info.certificate = cert_dict
                        info.issuer = self._format_x509_name(cert_dict.get('issuer', []))
                        info.subject = self._format_x509_name(cert_dict.get('subject', []))

                        if 'notBefore' in cert_dict:
                            try:
                                info.not_before = datetime.strptime(
                                    cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z'
                                )
                            except ValueError:
                                pass

                        if 'notAfter' in cert_dict:
                            try:
                                info.not_after = datetime.strptime(
                                    cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z'
                                )
                            except ValueError:
                                pass

                        san = cert_dict.get('subjectAltName', [])
                        for san_type, san_value in san:
                            if san_type == 'DNS':
                                info.san_domains.append(san_value)
                            elif san_type == 'IP Address':
                                info.san_ips.append(san_value)

                        info.serial_number = str(cert_dict.get('serialNumber', ''))

                    info.evidence.append(Evidence(
                        source="TLS Fingerprint",
                        finding=f"TLS certificate retrieved from port {port}",
                        evidence_type=EvidenceType.CONFIRMED,
                        raw_data={"issuer": info.issuer, "subject": info.subject}
                    ))

                    if info.san_ips:
                        info.evidence.append(Evidence(
                            source="TLS SAN",
                            finding=f"Certificate contains IP SANs: {', '.join(info.san_ips)}",
                            evidence_type=EvidenceType.STRONG,
                            raw_data=info.san_ips
                        ))

        except ssl.SSLError as e:
            info.evidence.append(Evidence(
                source="TLS Fingerprint",
                finding=f"SSL error on port {port}: {str(e)}",
                evidence_type=EvidenceType.WEAK
            ))
        except (socket.timeout, socket.error, ConnectionRefusedError):
            info.evidence.append(Evidence(
                source="TLS Fingerprint",
                finding=f"Could not establish TLS connection on port {port}",
                evidence_type=EvidenceType.WEAK
            ))

        return info

    def get_http_fingerprint(
        self,
        host: str,
        port: int = 80,
        use_https: bool = False,
        path: str = "/"
    ) -> HTTPFingerprint:

        fp = HTTPFingerprint(port=port)
        protocol = "https" if use_https else "http"
        url = f"{protocol}://{host}:{port}{path}"

        try:
            start_time = datetime.now()

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; TrueOrigin/1.0; Security Audit)',
                'Accept': '*/*',
                'Connection': 'close'
            })

            context = None
            if use_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=self.timeout, context=context) as response:
                fp.response_time_ms = (datetime.now() - start_time).total_seconds() * 1000
                fp.status_code = response.status

                for header, value in response.getheaders():
                    fp.headers[header.lower()] = value

                fp.server = fp.headers.get('server')
                fp.powered_by = fp.headers.get('x-powered-by')

                if 'content-length' in fp.headers:
                    try:
                        fp.content_length = int(fp.headers['content-length'])
                    except ValueError:
                        pass

                fp.cookies = [
                    v for k, v in response.getheaders()
                    if k.lower() == 'set-cookie'
                ]

                fp.evidence.append(Evidence(
                    source="HTTP Fingerprint",
                    finding=f"HTTP {fp.status_code} response from port {port}",
                    evidence_type=EvidenceType.CONFIRMED,
                    raw_data={"server": fp.server, "response_time_ms": fp.response_time_ms}
                ))

                # Check for IP leaks in headers
                ip_leak_headers = ['x-real-ip', 'x-forwarded-for', 'x-originating-ip',
                                   'x-client-ip', 'x-backend-server', 'x-server-ip']

                for header in ip_leak_headers:
                    if header in fp.headers:
                        ips = extract_ip_from_text(fp.headers[header])
                        if ips:
                            fp.evidence.append(Evidence(
                                source=f"HTTP Header: {header}",
                                finding=f"Potential origin IP leaked: {', '.join(ips)}",
                                evidence_type=EvidenceType.STRONG,
                                raw_data=ips
                            ))

        except urllib.error.HTTPError as e:
            fp.status_code = e.code
            fp.evidence.append(Evidence(
                source="HTTP Fingerprint",
                finding=f"HTTP error {e.code} from port {port}",
                evidence_type=EvidenceType.CONFIRMED
            ))
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
            fp.evidence.append(Evidence(
                source="HTTP Fingerprint",
                finding=f"Failed to connect to port {port}: {str(e)}",
                evidence_type=EvidenceType.WEAK
            ))

        return fp

    def _format_x509_name(self, x509_name: List) -> str:
        parts = []
        for rdn in x509_name:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts)

    def analyze_certificate_for_origin(self, tls_info: TLSInfo) -> List[Evidence]:
        evidence = []

        if not tls_info.has_tls:
            return evidence

        cdn_issuers = {
            'cloudflare': 'Cloudflare',
            'digicert': 'DigiCert (common for CDNs)',
            'globalsign': 'GlobalSign (common for CDNs)',
            'sectigo': 'Sectigo/Comodo',
            'amazon': 'Amazon/AWS',
            'google': 'Google',
            "let's encrypt": "Let's Encrypt"
        }

        if tls_info.issuer:
            issuer_lower = tls_info.issuer.lower()
            for pattern, cdn_name in cdn_issuers.items():
                if pattern in issuer_lower:
                    evidence.append(Evidence(
                        source="Certificate Issuer",
                        finding=f"Certificate issued by {cdn_name}",
                        evidence_type=EvidenceType.MODERATE,
                        raw_data=tls_info.issuer
                    ))
                    break

        if tls_info.san_ips:
            evidence.append(Evidence(
                source="Certificate SAN",
                finding=f"Certificate valid for IPs: {', '.join(tls_info.san_ips)}",
                evidence_type=EvidenceType.STRONG,
                raw_data=tls_info.san_ips
            ))

        if tls_info.san_domains:
            wildcards = [d for d in tls_info.san_domains if d.startswith('*.')]
            if wildcards:
                evidence.append(Evidence(
                    source="Certificate SAN",
                    finding=f"Wildcard certificate detected: {', '.join(wildcards[:3])}",
                    evidence_type=EvidenceType.MODERATE
                ))

        return evidence

    def compare_fingerprints(
        self,
        fp1: HTTPFingerprint,
        fp2: HTTPFingerprint
    ) -> List[Evidence]:
        evidence = []

        if fp1.server and fp2.server and fp1.server != fp2.server:
            evidence.append(Evidence(
                source="Server Header Comparison",
                finding=f"Different servers: port {fp1.port}='{fp1.server}' vs port {fp2.port}='{fp2.server}'",
                evidence_type=EvidenceType.MODERATE
            ))

        if fp1.response_time_ms and fp2.response_time_ms:
            diff = abs(fp1.response_time_ms - fp2.response_time_ms)
            if diff > 100:
                slower_port = fp1.port if fp1.response_time_ms > fp2.response_time_ms else fp2.port
                evidence.append(Evidence(
                    source="Response Time Comparison",
                    finding=f"Port {slower_port} is {diff:.0f}ms slower (possible proxy latency)",
                    evidence_type=EvidenceType.WEAK
                ))

        return evidence
