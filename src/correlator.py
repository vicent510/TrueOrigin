# Cross-port correlation module
# Identifies inconsistencies and origin indicators across ports.

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from .utils import Evidence, EvidenceType, PortInfo, OriginCandidate
from .proxy_detector import ProxyDetectionResult


@dataclass
class CorrelationResult:
    target_ip: str
    total_ports_analyzed: int
    proxied_ports: List[int] = field(default_factory=list)
    non_proxied_ports: List[int] = field(default_factory=list)
    inconsistencies: List[str] = field(default_factory=list)
    origin_candidates: List[OriginCandidate] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    confidence_score: float = 0.0


class CrossPortCorrelator:
    # Correlates findings across ports to reveal origin infrastructure.

    def __init__(self):
        self.direct_access_ports = {22, 21, 3306, 5432, 6379, 27017, 11211}
        self.web_ports = {80, 443, 8080, 8443, 8000, 8888}
        self.mail_ports = {25, 110, 143, 465, 587, 993, 995}
        self.admin_ports = {22, 3389, 5900, 5901}
        self.weak_direct_ports = set(self.web_ports)

    def correlate(
        self,
        target_ip: str,
        port_infos: List[PortInfo],
        proxy_results: Dict[int, ProxyDetectionResult]
    ) -> CorrelationResult:

        result = CorrelationResult(
            target_ip=target_ip,
            total_ports_analyzed=len(port_infos)
        )

        for port_info in port_infos:
            port = port_info.port
            if port in proxy_results:
                if proxy_results[port].is_proxied:
                    result.proxied_ports.append(port)
                else:
                    result.non_proxied_ports.append(port)

        self._analyze_non_proxied_ports(result, port_infos, proxy_results)
        self._detect_inconsistencies(result, port_infos, proxy_results)
        self._analyze_response_patterns(result, proxy_results)
        self._calculate_confidence(result)

        return result

    def _analyze_non_proxied_ports(
        self,
        result: CorrelationResult,
        port_infos: List[PortInfo],
        proxy_results: Dict[int, ProxyDetectionResult]
    ):
        # Non-web ports are stronger origin indicators than web ports
        if not result.non_proxied_ports:
            return

        web_like: List[int] = []
        direct_like: List[int] = []

        for port in result.non_proxied_ports:
            if port in self.weak_direct_ports:
                web_like.append(port)
            else:
                direct_like.append(port)

            port_info = next((p for p in port_infos if p.port == port), None)
            svc = (port_info.service or "unknown") if port_info else "unknown"

            if port in self.weak_direct_ports:
                ev_type = EvidenceType.MODERATE
                msg = (
                    f"Port {port} ({svc}) does not show strong proxy indicators. "
                    f"On web ports this may still be a CDN/edge endpoint; origin validation is required."
                )
            else:
                ev_type = EvidenceType.STRONG
                msg = (
                    f"Port {port} ({svc}) appears non-proxied on a non-web service, "
                    f"which can indicate direct/origin exposure."
                )

            result.evidence.append(Evidence(
                source=f"Non-Proxied Port: {port}",
                finding=msg,
                evidence_type=ev_type
            ))

        if direct_like:
            base_conf = 0.70
            reasoning = "Direct-looking (non-web) non-proxied service(s) detected on target IP"
            evidence_type = EvidenceType.STRONG
            ports_used = sorted(list(set(direct_like + web_like)))
        else:
            base_conf = 0.30
            reasoning = (
                "Only web ports appear non-proxied on the resolved IP. "
                "This does not prove origin access and may represent CDN/edge behavior."
            )
            evidence_type = EvidenceType.MODERATE
            ports_used = sorted(web_like)

        candidate = OriginCandidate(
            ip=result.target_ip,
            confidence_score=base_conf,
            source_ports=ports_used,
            reasoning=reasoning
        )

        candidate.evidence.append(Evidence(
            source="Cross-Port Correlation",
            finding=f"Non-proxied ports observed: web_like={sorted(web_like)} direct_like={sorted(direct_like)}",
            evidence_type=evidence_type
        ))

        if not direct_like and web_like:
            candidate.evidence.append(Evidence(
                source="Correlation Guardrail",
                finding="Non-proxied web ports alone are insufficient to confirm origin; use IP intelligence and origin validation.",
                evidence_type=EvidenceType.MODERATE
            ))

        result.origin_candidates.append(candidate)

    def _detect_inconsistencies(
        self,
        result: CorrelationResult,
        port_infos: List[PortInfo],
        proxy_results: Dict[int, ProxyDetectionResult]
    ):
        # Mixed proxy/non-proxy config is suspicious
        if result.proxied_ports and result.non_proxied_ports:
            inconsistency = (
                f"Mixed proxy configuration: ports {sorted(result.proxied_ports)} are proxied, "
                f"but ports {sorted(result.non_proxied_ports)} appear direct"
            )
            result.inconsistencies.append(inconsistency)
            result.evidence.append(Evidence(
                source="Configuration Inconsistency",
                finding=inconsistency,
                evidence_type=EvidenceType.STRONG
            ))

        # Different providers on different ports
        providers: Dict[str, List[int]] = {}
        for port, detection in proxy_results.items():
            if detection.provider:
                providers.setdefault(detection.provider, []).append(port)

        if len(providers) > 1:
            provider_summary = ", ".join(
                f"{p}: ports {sorted(ports)}" for p, ports in providers.items()
            )
            inconsistency = f"Multiple proxy providers detected: {provider_summary}"
            result.inconsistencies.append(inconsistency)
            result.evidence.append(Evidence(
                source="Provider Inconsistency",
                finding=inconsistency,
                evidence_type=EvidenceType.MODERATE
            ))

        for port_info in port_infos:
            if port_info.port in self.direct_access_ports:
                result.evidence.append(Evidence(
                    source="Service Analysis",
                    finding=f"Port {port_info.port} ({port_info.service}) typically implies direct service exposure",
                    evidence_type=EvidenceType.STRONG
                ))

    def _analyze_response_patterns(
        self,
        result: CorrelationResult,
        proxy_results: Dict[int, ProxyDetectionResult]
    ):
        response_times: List[Tuple[int, float]] = []
        servers: Dict[str, List[int]] = {}

        for port, detection in proxy_results.items():
            if detection.http_fingerprint:
                fp = detection.http_fingerprint
                if fp.response_time_ms:
                    response_times.append((port, fp.response_time_ms))
                if fp.server:
                    servers.setdefault(fp.server, []).append(port)

        if len(response_times) > 1:
            times = [t[1] for t in response_times]
            max_time = max(times)
            min_time = min(times)

            if max_time - min_time > 200:
                slow_port = max(response_times, key=lambda x: x[1])
                fast_port = min(response_times, key=lambda x: x[1])
                result.evidence.append(Evidence(
                    source="Response Time Analysis",
                    finding=(
                        f"Response time variance observed: port {fast_port[0]} ({fast_port[1]:.0f}ms) "
                        f"vs port {slow_port[0]} ({slow_port[1]:.0f}ms)"
                    ),
                    evidence_type=EvidenceType.WEAK
                ))

        if len(servers) > 1:
            result.evidence.append(Evidence(
                source="Server Header Correlation",
                finding=f"Multiple server signatures detected across ports: {list(servers.keys())}",
                evidence_type=EvidenceType.MODERATE
            ))

    def _calculate_confidence(self, result: CorrelationResult):
        score = 0.0

        non_proxied_web = [p for p in result.non_proxied_ports if p in self.weak_direct_ports]
        non_proxied_nonweb = [p for p in result.non_proxied_ports if p not in self.weak_direct_ports]

        if non_proxied_nonweb:
            score += min(0.45, len(non_proxied_nonweb) * 0.18)

        if non_proxied_web:
            score += min(0.15, len(non_proxied_web) * 0.05)

        if result.inconsistencies:
            score += min(0.30, len(result.inconsistencies) * 0.12)

        strong_evidence = sum(
            1 for e in result.evidence
            if e.evidence_type in (EvidenceType.CONFIRMED, EvidenceType.STRONG)
        )
        score += min(0.25, strong_evidence * 0.05)

        result.confidence_score = min(1.0, score)

        for candidate in result.origin_candidates:
            candidate.confidence_score = min(1.0, candidate.confidence_score + score * 0.10)

    def find_origin_from_ports(
        self,
        port_infos: List[PortInfo],
        proxy_results: Dict[int, ProxyDetectionResult]
    ) -> Optional[Tuple[str, List[int]]]:

        non_proxied: List[int] = []
        for port_info in port_infos:
            port = port_info.port
            if port in proxy_results and not proxy_results[port].is_proxied:
                non_proxied.append(port)

        if non_proxied:
            web_like = [p for p in non_proxied if p in self.weak_direct_ports]
            nonweb_like = [p for p in non_proxied if p not in self.weak_direct_ports]

            if nonweb_like:
                return (
                    f"Direct-looking (non-web) services appear non-proxied on {len(nonweb_like)} port(s)",
                    sorted(nonweb_like)
                )

            return (
                "Only web ports appear non-proxied; this may still be CDN/edge behavior and requires validation",
                sorted(web_like)
            )

        direct_services: List[int] = []
        for port_info in port_infos:
            if port_info.port in self.direct_access_ports:
                direct_services.append(port_info.port)

        if direct_services:
            return (
                "Services typically requiring direct access found (potential origin exposure)",
                sorted(direct_services)
            )

        return None
