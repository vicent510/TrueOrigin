# Output formatting module
# Console and JSON output with confidence indicators.

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .utils import Evidence, EvidenceType, PortInfo
from .scoring import ScoredCandidate


@dataclass
class AnalysisReport:
    target: str
    target_ip: str
    open_ports: List[Dict[str, Any]]
    candidates: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    created_at: str


class ResultFormatter:
    # Formats results for console and JSON output.

    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "gray": "\033[90m",
    }

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors

    def _c(self, color: str, text: str) -> str:
        if not self.use_colors or color not in self.COLORS:
            return text
        return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"

    def format_banner(self) -> str:
        banner = [
            "",
            "+" + "=" * 62 + "+",
            "|" + " " * 24 + "TrueOrigin" + " " * 28 + "|",
            "|" + " " * 11 + "Origin IP Discovery & Proxy Analysis" + " " * 14 + "|",
            "+" + "=" * 62 + "+",
        ]
        return "\n".join(banner)

    def format_section_header(self, title: str) -> str:
        line = "=" * 60
        return f"\n{line}\n{title}\n{line}"

    def format_validation_result(
        self,
        valid_format: bool,
        reachable: bool,
        target: str,
        resolved_ip: Optional[str],
        error_message: Optional[str] = None
    ) -> str:
        lines = [self.format_section_header("Target Validation")]
        lines.append(f"  Target: {target}")
        lines.append(f"  Valid Format: {'Y' if valid_format else 'N'}")
        lines.append(f"  Resolved IP: {resolved_ip if resolved_ip else 'N/A'}")
        if reachable:
            lines.append(f"  Status: {self._c('green', 'Reachable')}")
        else:
            lines.append(f"  Status: {self._c('red', 'Not Reachable')}")
        if error_message:
            lines.append(f"  Error: {self._c('red', error_message)}")
        return "\n".join(lines)

    def format_port_scan(self, open_ports: List[PortInfo]) -> str:
        lines = [self.format_section_header("Port Discovery")]

        if not open_ports:
            lines.append(f"  {self._c('yellow', 'No open ports found')}")
            return "\n".join(lines)

        lines.append(f"  Found {len(open_ports)} open port(s):\n")
        lines.append("  Port     Service         Status       Proxy")
        lines.append("  -------- --------------- ------------ --------------------")

        for port in open_ports:
            proxy_status = self._c("gray", "Unknown")
            if port.is_proxied is True:
                provider = port.proxy_provider or "Unknown"
                proxy_status = self._c("yellow", f"Yes ({provider})")
            elif port.is_proxied is False:
                proxy_status = self._c("green", "No (Low indicators)")

            lines.append(
                f"  {port.port:<8} {port.service or 'Unknown':<15} "
                f"{self._c('green', 'Open'):<12} {proxy_status}"
            )

        return "\n".join(lines)

    def format_proxy_analysis(
        self,
        proxied_ports: List[int],
        non_proxied_ports: List[int],
        providers: Dict[str, List[int]]
    ) -> str:
        lines = [self.format_section_header("Proxy Analysis")]

        if proxied_ports:
            lines.append(f"  {self._c('yellow', 'Proxied Ports')}: {', '.join(map(str, proxied_ports))}")
        if non_proxied_ports:
            lines.append(f"  {self._c('green', 'Ports With Low Proxy Indicators')}: {', '.join(map(str, non_proxied_ports))}")

        if providers:
            lines.append(f"\n  Detected Providers:")
            for provider, ports in providers.items():
                port_list = ", ".join(map(str, ports))
                lines.append(f"    - {provider}: {port_list}")

        if non_proxied_ports:
            web_ports = {80, 443, 8080, 8443, 8000, 8888}
            only_web = all(p in web_ports for p in non_proxied_ports)

            if only_web:
                lines.append(
                    f"\n  {self._c('yellow', '> Web ports show low proxy indicators. This may still be CDN/edge behavior.')}"
                )
            else:
                lines.append(
                    f"\n  {self._c('green', '> Non-web direct-looking ports detected. This can indicate direct/origin exposure.')}"
                )

        return "\n".join(lines)

    def format_origin_candidates(
        self,
        candidates: List[ScoredCandidate],
        current_ip: str
    ) -> str:
        lines = [self.format_section_header("Origin IP Candidates")]

        if not candidates:
            lines.append(f"  {self._c('yellow', 'No definitive origin IP candidates identified')}")
            lines.append(f"  Current IP ({current_ip}) appears to be behind proxy/CDN")
            return "\n".join(lines)

        for i, c in enumerate(candidates[:5], 1):
            is_edge = any("cdn/edge" in (w or "").lower() for w in (c.warnings or []))
            edge_tag = f" {self._c('yellow', '[EDGE/CDN]')}" if is_edge else ""

            if c.confidence_level == "high":
                conf_color = "green" if not is_edge else "yellow"
            elif c.confidence_level == "medium":
                conf_color = "yellow"
            else:
                conf_color = "red"

            lines.append(f"\n  #{i} {c.ip}{edge_tag}")
            lines.append(f"     Confidence: {self._c(conf_color, f'{c.final_score:.0%}')} ({c.confidence_level.upper()})")

            if c.reasoning:
                lines.append(f"     Reasoning: {c.reasoning}")

            if c.score_breakdown:
                top = sorted(c.score_breakdown.items(), key=lambda x: x[1], reverse=True)[:3]
                lines.append(f"     Key Factors: {', '.join([k for k, _v in top])}")

            if c.warnings:
                for w in c.warnings:
                    lines.append(f"     {self._c('yellow', '!')} {w}")

        return "\n".join(lines)

    def format_evidence_chain(self, evidence: List[Evidence], max_display: int = 15) -> str:
        lines = [self.format_section_header("Evidence Chain")]

        if not evidence:
            lines.append(f"  {self._c('yellow', 'No evidence collected')}")
            return "\n".join(lines)

        grouped: Dict[EvidenceType, List[Evidence]] = {
            EvidenceType.CONFIRMED: [],
            EvidenceType.STRONG: [],
            EvidenceType.MODERATE: [],
            EvidenceType.WEAK: [],
        }

        for e in evidence:
            grouped.setdefault(e.evidence_type, []).append(e)

        def render_group(title: str, evidences: List[Evidence]) -> None:
            lines.append(f"\n  {title} ({len(evidences)}):")
            for ev in evidences[:max_display]:
                lines.append(f"    - [{ev.source}] {ev.finding}")
            remaining = len(evidences) - max_display
            if remaining > 0:
                lines.append(f"    ... and {remaining} more findings")

        render_group("Confirmed Facts", grouped.get(EvidenceType.CONFIRMED, []))
        render_group("Strong Inferences", grouped.get(EvidenceType.STRONG, []))
        render_group("Moderate Indicators", grouped.get(EvidenceType.MODERATE, []))
        render_group("Weak Indicators", grouped.get(EvidenceType.WEAK, []))

        return "\n".join(lines)

    def format_recommendations(self, candidates: List[ScoredCandidate], has_direct_ports: bool) -> str:
        lines = [self.format_section_header("Recommendations")]

        if not candidates:
            lines.append("  - No origin candidates found - consider additional authorized validation methods")
            lines.append("  - Review proxy/CDN configuration and ensure origin is not publicly exposed")
            return "\n".join(lines)

        top = candidates[0]
        top_is_edge = any("cdn/edge" in (w or "").lower() for w in (top.warnings or []))

        if has_direct_ports:
            lines.append("  - Direct-looking port access detected - verify whether this exposure is intentional")
            lines.append("  - Consider restricting access to non-web ports at firewall level")

        if top_is_edge:
            lines.append(f"  - Top-ranked candidate appears to be CDN/edge: {top.ip} - validate origin using confirmed methods before acting")
        else:
            lines.append(f"  - Highest-confidence origin candidate: {top.ip} - verify and secure this address")

        lines.append("  - Treat results as inferences; corroborate with additional authorized evidence")
        return "\n".join(lines)

    def format_disclaimer(self) -> str:
        disclaimer = [
            "",
            "+" + "-" * 62 + "+",
            "|  DISCLAIMER: Results are inferences for authorized testing  |",
            "|  only. Always verify findings through additional means.     |",
            "+" + "-" * 62 + "+",
        ]
        return "\n".join(disclaimer)

    def to_json(
        self,
        target: str,
        target_ip: str,
        open_ports: List[PortInfo],
        candidates: List[ScoredCandidate],
        evidence: List[Evidence]
    ) -> str:
        report = {
            "meta": {
                "tool": "TrueOrigin",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "target_ip": target_ip
            },
            "open_ports": [
                {
                    "port": p.port,
                    "service": p.service,
                    "state": p.state,
                    "is_proxied": p.is_proxied,
                    "proxy_provider": p.proxy_provider
                }
                for p in open_ports
            ],
            "origin_candidates": [
                {
                    "ip": c.ip,
                    "confidence_score": c.final_score,
                    "confidence_level": c.confidence_level,
                    "reasoning": c.reasoning,
                    "score_breakdown": c.score_breakdown,
                    "warnings": c.warnings,
                    "is_edge_cdn": any("cdn/edge" in (w or "").lower() for w in (c.warnings or [])),
                }
                for c in candidates
            ],
            "evidence": [e.to_dict() for e in evidence],
            "disclaimer": "Results are inferences for authorized testing only"
        }

        return json.dumps(report, indent=2)

    def format_full_report(
        self,
        target: str,
        target_ip: str,
        open_ports: List[PortInfo],
        candidates: List[ScoredCandidate],
        evidence: List[Evidence]
    ) -> str:
        parts = [
            self.format_banner(),
            self.format_validation_result(True, True, target, target_ip),
            self.format_port_scan(open_ports),
            self.format_origin_candidates(candidates, target_ip),
            self.format_evidence_chain(evidence),
            self.format_recommendations(candidates, has_direct_ports=False),
            self.format_disclaimer()
        ]
        return "\n".join(parts)
