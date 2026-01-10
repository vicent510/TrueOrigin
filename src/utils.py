# Shared utilities for TrueOrigin
# Common functions for networking, logging, and data handling.

import socket
import logging
import re
import ipaddress
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

import json
import urllib.request
import urllib.error


class EvidenceType(Enum):
    CONFIRMED = "confirmed"   # Direct, verifiable evidence
    STRONG = "strong"         # High-confidence inference
    MODERATE = "moderate"     # Reasonable inference with caveats
    WEAK = "weak"             # Indicator only, requires corroboration


@dataclass
class Evidence:
    source: str
    finding: str
    evidence_type: EvidenceType
    raw_data: Optional[Any] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "finding": self.finding,
            "type": self.evidence_type.value,
            "raw_data": str(self.raw_data) if self.raw_data else None,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class PortInfo:
    port: int
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None
    is_proxied: Optional[bool] = None
    proxy_provider: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class OriginCandidate:
    ip: str
    confidence_score: float
    evidence: List[Evidence] = field(default_factory=list)
    source_ports: List[int] = field(default_factory=list)
    reasoning: str = ""

    # Enrichment fields for RDAP data
    asn: Optional[str] = None
    org: Optional[str] = None
    network_name: Optional[str] = None
    country: Optional[str] = None
    is_cdn_edge: bool = False
    provider_hint: Optional[str] = None


def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S"
    )
    return logging.getLogger("TrueOrigin")


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    pattern = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_all_ips_for_domain(domain: str) -> List[str]:
    # Resolve domain to all IPv4 addresses via system resolver
    ips: List[str] = []
    if not domain or not is_valid_domain(domain):
        return ips

    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for info in infos:
            sockaddr = info[4]
            if sockaddr and len(sockaddr) >= 1:
                ip = sockaddr[0]
                if is_valid_ip(ip):
                    ips.append(ip)
    except socket.gaierror:
        return []

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def resolve_target(target: str) -> Tuple[Optional[str], Optional[str]]:
    # Returns (resolved_ip, target_type) where target_type is "ip" or "domain"
    if not target:
        return None, None

    if is_valid_ip(target):
        return target, "ip"

    if is_valid_domain(target):
        ip = resolve_domain(target)
        return (ip, "domain") if ip else (None, "domain")

    return None, None


def extract_ip_from_text(text: str) -> List[str]:
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    candidates = re.findall(ipv4_pattern, text)
    return [ip for ip in candidates if is_valid_ip(ip)]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return False


def get_ip_info(ip: str) -> Dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
        return {
            "ip": ip,
            "version": addr.version,
            "is_private": addr.is_private,
            "is_global": addr.is_global,
            "is_loopback": addr.is_loopback,
            "is_reserved": addr.is_reserved,
        }
    except ValueError:
        return {"ip": ip, "error": "Invalid IP"}


# CDN/edge provider keywords for RDAP classification
_CDN_KEYWORDS: Dict[str, List[str]] = {
    "cloudflare": ["cloudflare", "cloudflare, inc", "as13335"],
    "akamai": ["akamai", "as20940"],
    "fastly": ["fastly", "as54113"],
    "amazon": ["amazon", "aws", "cloudfront", "as16509", "as14618"],
    "google": ["google", "gstatic", "as15169"],
    "microsoft": ["microsoft", "azure", "as8075"],
    "stackpath": ["stackpath", "netdna", "as12989"],
    "imperva": ["imperva", "incapsula", "as19551"],
    "sucuri": ["sucuri"],
}


def _http_get_json(url: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "TrueOrigin/1.0 (RDAP client; authorized security testing)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) >= 400:
                return None
            data = resp.read()
        return json.loads(data.decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        return None


def lookup_rdap(ip: str, timeout: float = 5.0) -> Dict[str, Any]:
    # Lightweight RDAP lookup for IP attribution
    if not is_valid_ip(ip):
        return {"ip": ip, "error": "Invalid IP"}

    url = f"https://rdap.org/ip/{ip}"
    raw = _http_get_json(url, timeout=timeout)
    if not raw:
        return {"ip": ip, "error": "RDAP lookup failed"}

    name = raw.get("name") or raw.get("handle") or None
    country = raw.get("country") or None

    # Extract organization from vCard
    org = None
    entities = raw.get("entities") or []
    for ent in entities:
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
                    if isinstance(item[3], str) and item[3].strip():
                        org = item[3].strip()
                        break
        if org:
            break

    # Extract ASN if present
    asn = None
    for k in ("asn", "autnum", "autonomousSystemNumber"):
        if k in raw:
            try:
                asn = str(raw[k])
                break
            except Exception:
                pass

    return {
        "ip": ip,
        "asn": asn,
        "org": org,
        "network_name": name,
        "country": country,
        "raw": raw,
    }


def classify_edge_provider(asn: Optional[str], org: Optional[str], network_name: Optional[str]) -> Tuple[bool, Optional[str]]:
    hay = " ".join([str(asn or ""), str(org or ""), str(network_name or "")]).lower()
    for provider, keys in _CDN_KEYWORDS.items():
        if any(k in hay for k in keys):
            return True, provider
    return False, None


def enrich_candidate_with_rdap(candidate: "OriginCandidate", timeout: float = 5.0) -> List[Evidence]:
    # Enrich candidate with RDAP data and return evidence
    evidence: List[Evidence] = []
    rdap = lookup_rdap(candidate.ip, timeout=timeout)

    if rdap.get("error"):
        evidence.append(Evidence(
            source="RDAP",
            finding=f"RDAP enrichment unavailable for {candidate.ip}: {rdap.get('error')}",
            evidence_type=EvidenceType.WEAK,
        ))
        return evidence

    candidate.asn = rdap.get("asn")
    candidate.org = rdap.get("org")
    candidate.network_name = rdap.get("network_name")
    candidate.country = rdap.get("country")

    is_edge, provider = classify_edge_provider(candidate.asn, candidate.org, candidate.network_name)
    candidate.is_cdn_edge = is_edge
    candidate.provider_hint = provider

    if is_edge:
        evidence.append(Evidence(
            source="RDAP",
            finding=f"IP {candidate.ip} appears to belong to a CDN/edge provider ({provider})",
            evidence_type=EvidenceType.STRONG,
            raw_data={
                "asn": candidate.asn,
                "org": candidate.org,
                "network": candidate.network_name,
                "country": candidate.country,
            },
        ))
    else:
        evidence.append(Evidence(
            source="RDAP",
            finding=f"IP {candidate.ip} appears to be non-CDN infrastructure (potential origin hosting)",
            evidence_type=EvidenceType.MODERATE,
            raw_data={
                "asn": candidate.asn,
                "org": candidate.org,
                "network": candidate.network_name,
                "country": candidate.country,
            },
        ))

    return evidence


def safe_socket_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.error, socket.timeout):
        return False


def merge_evidence(existing: List[Evidence], new: List[Evidence]) -> List[Evidence]:
    seen = {(e.source, e.finding) for e in existing}
    merged = list(existing)
    for e in new:
        if (e.source, e.finding) not in seen:
            merged.append(e)
            seen.add((e.source, e.finding))
    return merged
