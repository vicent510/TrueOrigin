# Proxy and CDN detection module
# Identifies proxy providers via headers, certificates, and heuristics.

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .utils import Evidence, EvidenceType, PortInfo
from .fingerprint import Fingerprinter, HTTPFingerprint, TLSInfo


@dataclass
class ProxyDetectionResult:
    port: int
    is_proxied: bool
    confidence: float
    provider: Optional[str] = None
    provider_confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    http_fingerprint: Optional[HTTPFingerprint] = None
    tls_info: Optional[TLSInfo] = None


class ProxyDetector:
    # Detects CDN/proxy presence using headers, certs, and behavioral analysis.

    PROVIDER_HEADERS = {
        'cloudflare': {
            'cf-ray': r'.*',
            'cf-cache-status': r'.*',
            'cf-request-id': r'.*',
            'server': r'cloudflare',
            'cf-connecting-ip': r'.*',
        },
        'akamai': {
            'x-akamai-transformed': r'.*',
            'x-akamai-request-id': r'.*',
            'server': r'akamai|akamaiGhost|AkamaiNetStorage',
            'x-cache': r'.*akamai.*',
        },
        'fastly': {
            'x-served-by': r'cache-.*',
            'x-cache': r'.*',
            'x-fastly-request-id': r'.*',
            'fastly-debug-digest': r'.*',
            'server': r'.*fastly.*',
        },
        'aws_cloudfront': {
            'x-amz-cf-id': r'.*',
            'x-amz-cf-pop': r'.*',
            'x-cache': r'.*cloudfront.*',
            'via': r'.*cloudfront.*',
            'server': r'Amazon.*|CloudFront',
        },
        'aws_alb': {
            'server': r'awselb.*',
        },
        'google_cloud': {
            'via': r'.*google.*',
            'server': r'gws|gse|Google Frontend',
            'x-goog-.*': r'.*',
        },
        'azure_cdn': {
            'x-msedge-ref': r'.*',
            'x-azure-ref': r'.*',
            'server': r'.*Microsoft.*|Azure',
        },
        'sucuri': {
            'x-sucuri-id': r'.*',
            'x-sucuri-cache': r'.*',
            'server': r'Sucuri.*',
        },
        'incapsula': {
            'x-iinfo': r'.*',
            'x-cdn': r'Incapsula',
            'server': r'.*Incapsula.*',
        },
        'stackpath': {
            'x-hw': r'.*',
            'server': r'NetDNA.*|StackPath.*|MaxCDN.*',
        },
        'nginx_proxy': {
            'server': r'^nginx.*',
            'x-nginx-.*': r'.*',
        },
        'varnish': {
            'x-varnish': r'.*',
            'via': r'.*varnish.*',
            'server': r'.*Varnish.*',
        },
        'haproxy': {
            'server': r'.*HAProxy.*',
        },
    }

    CERT_ISSUERS = {
        'cloudflare': ['cloudflare', 'cf-'],
        'amazon': ['amazon', 'aws'],
        'google': ['google', 'gts'],
        'akamai': ['akamai', 'cybertrust'],
        'digicert': ['digicert'],
        'sectigo': ['sectigo', 'comodo'],
    }

    PROXY_INDICATORS = [
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-forwarded-host',
        'x-real-ip',
        'x-proxy-id',
        'via',
        'x-cache',
        'x-cache-hit',
        'x-served-by',
        'x-cdn',
        'x-edge-.*',
    ]

    PROXIED_THRESHOLD = 0.45
    PROVIDER_FORCE_THRESHOLD = 0.25

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.fingerprinter = Fingerprinter(timeout=timeout)

    def detect(
        self,
        host: str,
        port: int,
        use_https: bool = None
    ) -> ProxyDetectionResult:

        result = ProxyDetectionResult(port=port, is_proxied=False, confidence=0.0)

        if use_https is None:
            use_https = port in [443, 8443, 9443, 4443]

        http_fp = self.fingerprinter.get_http_fingerprint(host, port, use_https=use_https)
        result.http_fingerprint = http_fp
        result.evidence.extend(http_fp.evidence)

        if use_https or port in [443, 8443]:
            tls_info = self.fingerprinter.get_tls_info(host, port)
            result.tls_info = tls_info
            result.evidence.extend(tls_info.evidence)

        header_score, header_evidence = self._analyze_headers(http_fp.headers, port)
        result.evidence.extend(header_evidence)

        provider, provider_conf, provider_evidence = self._identify_provider(http_fp.headers, result.tls_info)
        result.evidence.extend(provider_evidence)

        if provider:
            result.provider = provider
            result.provider_confidence = provider_conf

        tls_score = 0.0
        if result.tls_info and result.tls_info.has_tls:
            tls_score, tls_evidence = self._analyze_tls(result.tls_info)
            result.evidence.extend(tls_evidence)

        result.confidence = self._combine_scores(
            header_score=header_score,
            tls_score=tls_score,
            provider_conf=provider_conf
        )

        if provider and provider_conf >= self.PROVIDER_FORCE_THRESHOLD:
            result.is_proxied = True
        else:
            result.is_proxied = result.confidence >= self.PROXIED_THRESHOLD

        if result.is_proxied:
            provider_label = f" ({result.provider})" if result.provider else ""
            result.evidence.append(Evidence(
                source="Proxy Detection",
                finding=f"Port {port} appears to be proxied{provider_label} (confidence: {result.confidence:.0%})",
                evidence_type=EvidenceType.STRONG if result.confidence >= 0.7 else EvidenceType.MODERATE
            ))
        else:
            result.evidence.append(Evidence(
                source="Proxy Detection",
                finding=f"Port {port} does not show strong proxy indicators (confidence: {result.confidence:.0%})",
                evidence_type=EvidenceType.MODERATE
            ))

        return result

    def _combine_scores(self, header_score: float, tls_score: float, provider_conf: float) -> float:
        header_score = max(0.0, min(1.0, header_score))
        tls_score = max(0.0, min(1.0, tls_score))
        provider_conf = max(0.0, min(1.0, provider_conf))

        combined = (0.40 * provider_conf) + (0.35 * header_score) + (0.25 * tls_score)
        return max(0.0, min(1.0, combined))

    def _analyze_headers(self, headers: Dict[str, str], port: int) -> Tuple[float, List[Evidence]]:
        evidence: List[Evidence] = []
        score = 0.0

        for indicator in self.PROXY_INDICATORS:
            pattern = re.compile(indicator, re.IGNORECASE)
            for header_name in headers:
                if pattern.match(header_name):
                    score += 0.15
                    evidence.append(Evidence(
                        source=f"HTTP Header: {header_name}",
                        finding=f"Proxy indicator header detected: {header_name}",
                        evidence_type=EvidenceType.MODERATE,
                        raw_data=headers.get(header_name)
                    ))

        server = headers.get('server', '').lower()
        proxy_servers = ['nginx', 'varnish', 'haproxy', 'squid', 'traefik', 'envoy']
        for ps in proxy_servers:
            if ps and ps in server:
                score += 0.10
                evidence.append(Evidence(
                    source="Server Header",
                    finding=f"Common proxy/load balancer software detected: {ps}",
                    evidence_type=EvidenceType.WEAK,
                    raw_data={"server": headers.get("server", "")}
                ))

        return min(score, 1.0), evidence

    def _identify_provider(
        self,
        headers: Dict[str, str],
        tls_info: Optional[TLSInfo]
    ) -> Tuple[Optional[str], float, List[Evidence]]:

        evidence: List[Evidence] = []
        best_provider: Optional[str] = None
        best_confidence = 0.0

        for provider, patterns in self.PROVIDER_HEADERS.items():
            matches = 0
            total = len(patterns)

            for header_pattern, value_pattern in patterns.items():
                header_regex = re.compile(header_pattern, re.IGNORECASE)

                for header_name, header_value in headers.items():
                    if header_regex.match(header_name):
                        if re.search(value_pattern, str(header_value), re.IGNORECASE):
                            matches += 1
                            evidence.append(Evidence(
                                source=f"Provider Detection: {provider}",
                                finding=f"Header match: {header_name}={str(header_value)[:50]}",
                                evidence_type=EvidenceType.STRONG,
                                raw_data={header_name: header_value}
                            ))
                            break

            if matches > 0:
                confidence = matches / max(total, 1)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_provider = provider

        if tls_info and tls_info.issuer:
            issuer_lower = tls_info.issuer.lower()
            for provider, patterns in self.CERT_ISSUERS.items():
                if any(p in issuer_lower for p in patterns):
                    if not best_provider or best_confidence < 0.5:
                        best_provider = f"{provider}_cert"
                        best_confidence = max(best_confidence, 0.4)
                        evidence.append(Evidence(
                            source="Certificate Issuer",
                            finding=f"Certificate issuer suggests {provider} infrastructure",
                            evidence_type=EvidenceType.MODERATE,
                            raw_data=tls_info.issuer
                        ))
                    break

        if best_provider:
            evidence.append(Evidence(
                source="Provider Identification",
                finding=f"Identified provider: {best_provider.upper()} (confidence: {best_confidence:.0%})",
                evidence_type=EvidenceType.STRONG if best_confidence >= 0.7 else EvidenceType.MODERATE
            ))

        return best_provider, best_confidence, evidence

    def _analyze_tls(self, tls_info: TLSInfo) -> Tuple[float, List[Evidence]]:
        evidence: List[Evidence] = []
        score = 0.0

        if not tls_info.has_tls:
            return score, evidence

        if tls_info.san_domains:
            wildcards = [d for d in tls_info.san_domains if d.startswith('*.')]
            if wildcards:
                score += 0.20
                evidence.append(Evidence(
                    source="TLS Analysis",
                    finding=f"Wildcard certificate detected ({len(wildcards)} wildcard SAN entries)",
                    evidence_type=EvidenceType.MODERATE,
                    raw_data={"wildcards": wildcards[:10]}
                ))

        if tls_info.san_domains and len(tls_info.san_domains) > 10:
            score += 0.30
            evidence.append(Evidence(
                source="TLS Analysis",
                finding=f"Certificate has {len(tls_info.san_domains)} SAN entries (possible shared certificate)",
                evidence_type=EvidenceType.MODERATE
            ))

        cert_evidence = self.fingerprinter.analyze_certificate_for_origin(tls_info)
        evidence.extend(cert_evidence)
        if cert_evidence:
            score += min(0.30, 0.10 * len(cert_evidence))

        return min(score, 1.0), evidence

    def detect_all_ports(self, host: str, ports: List[PortInfo]) -> Dict[int, ProxyDetectionResult]:
        results: Dict[int, ProxyDetectionResult] = {}

        for port_info in ports:
            port = port_info.port
            use_https = port in [443, 8443, 9443, 4443] or 'HTTPS' in (port_info.service or '')

            result = self.detect(host, port, use_https=use_https)
            results[port] = result

            port_info.is_proxied = result.is_proxied
            port_info.proxy_provider = result.provider
            port_info.evidence.extend(result.evidence)

        return results

    def get_non_proxied_ports(self, detection_results: Dict[int, ProxyDetectionResult]) -> List[int]:
        return [port for port, result in detection_results.items() if not result.is_proxied]

    def get_proxied_ports(self, detection_results: Dict[int, ProxyDetectionResult]) -> List[Tuple[int, str, float]]:
        return [
            (port, result.provider or "Unknown", result.confidence)
            for port, result in detection_results.items()
            if result.is_proxied
        ]
