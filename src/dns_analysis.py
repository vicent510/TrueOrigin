# DNS analysis module
# Reverse lookups, subdomain enumeration, and mail server discovery.

import socket
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from .utils import Evidence, EvidenceType, is_valid_ip


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None


@dataclass
class DNSAnalysisResult:
    target: str
    forward_ips: List[str] = field(default_factory=list)
    reverse_names: Dict[str, List[str]] = field(default_factory=dict)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    origin_candidates: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


class DNSAnalyzer:
    # DNS-based origin discovery via subdomains and mail servers.

    ORIGIN_SUBDOMAINS = [
        'direct', 'origin', 'backend', 'server', 'real',
        'www2', 'old', 'dev', 'staging', 'test', 'api',
        'admin', 'mail', 'smtp', 'mx', 'ftp', 'cpanel',
        'webmail', 'email', 'pop', 'imap', 'ns1', 'ns2',
        'vpn', 'ssh', 'rdp', 'remote', 'internal',
        'panel', 'portal', 'secure', 'login', 'auth'
    ]

    CDN_PATTERNS = [
        r'cloudflare',
        r'akamai',
        r'fastly',
        r'cloudfront',
        r'edgecast',
        r'cdn',
        r'cache',
        r'edge',
        r'waf',
    ]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)

    def analyze(self, target: str, resolved_ip: str = None) -> DNSAnalysisResult:
        result = DNSAnalysisResult(target=target)

        if is_valid_ip(target):
            result.forward_ips = [target]
            self._reverse_lookup(target, result)
        else:
            self._forward_lookup(target, result)
            self._analyze_subdomains(target, result)
            self._analyze_mail_records(target, result)
            self._analyze_ns_records(target, result)

            for ip in result.forward_ips:
                self._reverse_lookup(ip, result)

        self._identify_origin_candidates(result)

        return result

    def _forward_lookup(self, domain: str, result: DNSAnalysisResult):
        try:
            ips = set()
            addr_info = socket.getaddrinfo(domain, None)
            for info in addr_info:
                ip = info[4][0]
                if is_valid_ip(ip):
                    ips.add(ip)

            result.forward_ips = list(ips)

            if result.forward_ips:
                result.evidence.append(Evidence(
                    source="Forward DNS",
                    finding=f"Domain resolves to {len(result.forward_ips)} IP(s): {', '.join(result.forward_ips[:5])}",
                    evidence_type=EvidenceType.CONFIRMED,
                    raw_data=result.forward_ips
                ))
        except socket.gaierror as e:
            result.evidence.append(Evidence(
                source="Forward DNS",
                finding=f"Forward lookup failed: {str(e)}",
                evidence_type=EvidenceType.WEAK
            ))

    def _reverse_lookup(self, ip: str, result: DNSAnalysisResult):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)

            if ip not in result.reverse_names:
                result.reverse_names[ip] = []
            result.reverse_names[ip].append(hostname)

            is_cdn = any(
                re.search(pattern, hostname, re.IGNORECASE)
                for pattern in self.CDN_PATTERNS
            )

            if is_cdn:
                result.evidence.append(Evidence(
                    source="Reverse DNS",
                    finding=f"IP {ip} has CDN-related hostname: {hostname}",
                    evidence_type=EvidenceType.STRONG
                ))
            else:
                result.evidence.append(Evidence(
                    source="Reverse DNS",
                    finding=f"IP {ip} resolves to: {hostname}",
                    evidence_type=EvidenceType.CONFIRMED
                ))

        except socket.herror:
            result.evidence.append(Evidence(
                source="Reverse DNS",
                finding=f"No PTR record for {ip}",
                evidence_type=EvidenceType.WEAK
            ))

    def _analyze_subdomains(self, domain: str, result: DNSAnalysisResult):
        # Check subdomains that often bypass CDN
        origin_ips = set()
        base_ips = set(result.forward_ips)

        for subdomain in self.ORIGIN_SUBDOMAINS:
            fqdn = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                if ip and ip not in base_ips:
                    origin_ips.add(ip)
                    result.evidence.append(Evidence(
                        source="Subdomain Enumeration",
                        finding=f"Subdomain {fqdn} resolves to different IP: {ip}",
                        evidence_type=EvidenceType.STRONG,
                        raw_data={"subdomain": fqdn, "ip": ip}
                    ))
            except socket.gaierror:
                pass

        result.origin_candidates.extend(list(origin_ips))

    def _analyze_mail_records(self, domain: str, result: DNSAnalysisResult):
        # Mail servers often point to origin infrastructure
        try:
            mail_subdomains = ['mail', 'smtp', 'mx', 'mx1', 'mx2', 'email']

            for sub in mail_subdomains:
                fqdn = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    if ip:
                        result.mx_records.append(fqdn)
                        if ip not in result.forward_ips:
                            result.origin_candidates.append(ip)
                            result.evidence.append(Evidence(
                                source="Mail Server Analysis",
                                finding=f"Mail subdomain {fqdn} resolves to {ip} (potential origin)",
                                evidence_type=EvidenceType.STRONG,
                                raw_data={"mail_host": fqdn, "ip": ip}
                            ))
                except socket.gaierror:
                    pass

        except Exception as e:
            result.evidence.append(Evidence(
                source="Mail Server Analysis",
                finding=f"Mail record analysis limited: {str(e)}",
                evidence_type=EvidenceType.WEAK
            ))

    def _analyze_ns_records(self, domain: str, result: DNSAnalysisResult):
        ns_subdomains = ['ns1', 'ns2', 'dns1', 'dns2', 'ns']

        for ns in ns_subdomains:
            fqdn = f"{ns}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                if ip:
                    result.ns_records.append(fqdn)
                    result.evidence.append(Evidence(
                        source="NS Analysis",
                        finding=f"Nameserver {fqdn} resolves to {ip}",
                        evidence_type=EvidenceType.MODERATE,
                        raw_data={"ns": fqdn, "ip": ip}
                    ))
            except socket.gaierror:
                pass

    def _identify_origin_candidates(self, result: DNSAnalysisResult):
        candidates = set()

        for ip, hostnames in result.reverse_names.items():
            for hostname in hostnames:
                is_cdn = any(
                    re.search(pattern, hostname, re.IGNORECASE)
                    for pattern in self.CDN_PATTERNS
                )
                if not is_cdn:
                    candidates.add(ip)

        candidates.update(result.origin_candidates)
        result.origin_candidates = list(candidates)

        if result.origin_candidates:
            result.evidence.append(Evidence(
                source="DNS Origin Discovery",
                finding=f"Identified {len(result.origin_candidates)} potential origin IP(s) via DNS",
                evidence_type=EvidenceType.MODERATE,
                raw_data=result.origin_candidates
            ))

    def quick_origin_check(self, domain: str) -> List[str]:
        # Quick check for common origin-exposing subdomains
        origin_ips = []
        try:
            main_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return origin_ips

        priority_subdomains = ['direct', 'origin', 'mail', 'ftp', 'cpanel', 'webmail']

        for sub in priority_subdomains:
            try:
                ip = socket.gethostbyname(f"{sub}.{domain}")
                if ip != main_ip and ip not in origin_ips:
                    origin_ips.append(ip)
            except socket.gaierror:
                pass

        return origin_ips

    def get_asn_info(self, ip: str) -> Optional[Dict]:
        # Placeholder for external API integration
        return {
            "ip": ip,
            "note": "ASN lookup requires external API integration (e.g., ipinfo.io, whois)"
        }
