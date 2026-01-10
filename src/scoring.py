# Confidence scoring module
# Weighted scoring for origin IP candidates.

from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .utils import Evidence, EvidenceType, OriginCandidate


class EvidenceCategory(Enum):
    DIRECT_ACCESS = "direct_access"
    DNS_DISCOVERY = "dns_discovery"
    HEADER_LEAK = "header_leak"
    CERTIFICATE = "certificate"
    CORRELATION = "correlation"
    INFRASTRUCTURE = "infrastructure"
    BEHAVIORAL = "behavioral"
    HISTORICAL = "historical"


@dataclass
class ScoringWeight:
    evidence_type: EvidenceType
    base_weight: float
    category_multipliers: Dict[EvidenceCategory, float] = field(default_factory=dict)


@dataclass
class ScoredCandidate:
    ip: str
    final_score: float
    confidence_level: str  # high, medium, low
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    evidence_summary: List[str] = field(default_factory=list)
    reasoning: str = ""
    warnings: List[str] = field(default_factory=list)


class ConfidenceScorer:
    # Calculates confidence scores with transparent reasoning.

    EVIDENCE_WEIGHTS = {
        EvidenceType.CONFIRMED: 1.0,
        EvidenceType.STRONG: 0.75,
        EvidenceType.MODERATE: 0.5,
        EvidenceType.WEAK: 0.25,
    }

    CATEGORY_WEIGHTS = {
        EvidenceCategory.DIRECT_ACCESS: 1.5,
        EvidenceCategory.HEADER_LEAK: 1.4,
        EvidenceCategory.DNS_DISCOVERY: 1.2,
        EvidenceCategory.CERTIFICATE: 1.1,
        EvidenceCategory.CORRELATION: 1.0,
        EvidenceCategory.INFRASTRUCTURE: 0.9,
        EvidenceCategory.BEHAVIORAL: 0.6,
        EvidenceCategory.HISTORICAL: 0.5,
    }

    CONFIDENCE_THRESHOLDS = {
        "high": 0.75,
        "medium": 0.45,
        "low": 0.0
    }

    EDGE_ORIGIN_CAP_DEFAULT = 0.35
    EDGE_ORIGIN_CAP_WITH_CONFIRMATION = 0.75

    def __init__(self):
        self.source_category_map = self._build_source_category_map()

    def _build_source_category_map(self) -> Dict[str, EvidenceCategory]:
        return {
            "non-proxied": EvidenceCategory.DIRECT_ACCESS,
            "direct": EvidenceCategory.DIRECT_ACCESS,
            "tcp probe": EvidenceCategory.DIRECT_ACCESS,

            "dns": EvidenceCategory.DNS_DISCOVERY,
            "subdomain": EvidenceCategory.DNS_DISCOVERY,
            "reverse": EvidenceCategory.DNS_DISCOVERY,
            "mail": EvidenceCategory.DNS_DISCOVERY,

            "certificate": EvidenceCategory.CERTIFICATE,
            "tls": EvidenceCategory.CERTIFICATE,
            "san": EvidenceCategory.CERTIFICATE,

            "header": EvidenceCategory.HEADER_LEAK,
            "x-real-ip": EvidenceCategory.HEADER_LEAK,
            "x-forwarded": EvidenceCategory.HEADER_LEAK,

            "correlation": EvidenceCategory.CORRELATION,
            "cross-port": EvidenceCategory.CORRELATION,
            "inconsistency": EvidenceCategory.CORRELATION,

            "fingerprint": EvidenceCategory.INFRASTRUCTURE,
            "server": EvidenceCategory.INFRASTRUCTURE,
            "asn": EvidenceCategory.INFRASTRUCTURE,
            "rdap": EvidenceCategory.INFRASTRUCTURE,
            "infrastructure": EvidenceCategory.INFRASTRUCTURE,
            "hosting": EvidenceCategory.INFRASTRUCTURE,

            "behavioral": EvidenceCategory.BEHAVIORAL,
            "response": EvidenceCategory.BEHAVIORAL,

            "historical": EvidenceCategory.HISTORICAL,
            "passive": EvidenceCategory.HISTORICAL,
        }

    def score_candidates(self, candidates: List[OriginCandidate]) -> List[ScoredCandidate]:
        scored: List[ScoredCandidate] = []

        for candidate in candidates:
            scored_candidate = self._score_single_candidate(candidate)
            scored.append(scored_candidate)

        scored.sort(key=lambda c: c.final_score, reverse=True)
        return scored

    def _score_single_candidate(self, candidate: OriginCandidate) -> ScoredCandidate:
        total_score = 0.0
        max_possible = 0.0
        score_breakdown: Dict[str, float] = {}
        evidence_summary: List[str] = []
        warnings: List[str] = []

        is_edge = bool(getattr(candidate, "is_cdn_edge", False))
        provider_hint = getattr(candidate, "provider_hint", None)

        has_confirmed_validation = self._has_confirmed_origin_validation(candidate.evidence)

        for ev in candidate.evidence:
            category = self._categorize_evidence(ev)
            base_weight = self.EVIDENCE_WEIGHTS.get(ev.evidence_type, 0.25)
            category_multiplier = self.CATEGORY_WEIGHTS.get(category, 1.0)

            # DIRECT_ACCESS on CDN IPs is weak evidence
            if is_edge and category == EvidenceCategory.DIRECT_ACCESS:
                category_multiplier *= 0.15

            weighted_score = base_weight * category_multiplier

            category_name = category.value
            score_breakdown[category_name] = score_breakdown.get(category_name, 0.0) + weighted_score

            total_score += weighted_score
            max_possible += 1.5

            evidence_summary.append(
                f"[{ev.evidence_type.value}] {ev.source}: {ev.finding}"
            )

        if max_possible > 0:
            normalized_score = min(1.0, total_score / (max_possible * 0.5))
        else:
            normalized_score = candidate.confidence_score

        final_score = (normalized_score * 0.7) + (candidate.confidence_score * 0.3)

        if not candidate.evidence:
            warnings.append("No supporting evidence - score based on discovery method only")

        weak_only = all(
            e.evidence_type in (EvidenceType.WEAK, EvidenceType.MODERATE)
            for e in candidate.evidence
        )
        if weak_only and candidate.evidence:
            warnings.append("Evidence quality is weak/moderate only - confidence may be overstated")

        if is_edge:
            provider_str = f" ({provider_hint})" if provider_hint else ""
            warnings.append(f"Candidate appears to be a CDN/edge IP{provider_str} - origin confidence is capped")

            cap = self.EDGE_ORIGIN_CAP_WITH_CONFIRMATION if has_confirmed_validation else self.EDGE_ORIGIN_CAP_DEFAULT
            final_score = min(final_score, cap)

        confidence_level = self._get_confidence_level(final_score)

        reasoning = candidate.reasoning or "Score derived from weighted evidence categories and candidate context"

        return ScoredCandidate(
            ip=candidate.ip,
            final_score=final_score,
            confidence_level=confidence_level,
            score_breakdown=score_breakdown,
            evidence_summary=evidence_summary,
            reasoning=reasoning,
            warnings=warnings
        )

    def _categorize_evidence(self, evidence: Evidence) -> EvidenceCategory:
        src = (evidence.source or "").lower()
        finding = (evidence.finding or "").lower()
        combined = f"{src} {finding}"

        for key, category in self.source_category_map.items():
            if key in combined:
                return category

        return EvidenceCategory.INFRASTRUCTURE

    def _has_confirmed_origin_validation(self, evidence_list: List[Evidence]) -> bool:
        for ev in evidence_list:
            if ev.evidence_type == EvidenceType.CONFIRMED:
                txt = f"{(ev.source or '').lower()} {(ev.finding or '').lower()}"
                if "validation" in txt or "validated" in txt or "content match" in txt or "matches" in txt:
                    return True
        return False

    def _get_confidence_level(self, score: float) -> str:
        if score >= self.CONFIDENCE_THRESHOLDS["high"]:
            return "high"
        elif score >= self.CONFIDENCE_THRESHOLDS["medium"]:
            return "medium"
        else:
            return "low"

    def explain_score(self, scored_candidate: ScoredCandidate) -> str:
        lines = [
            f"IP: {scored_candidate.ip}",
            f"Final Score: {scored_candidate.final_score:.0%} ({scored_candidate.confidence_level.upper()})",
            "Score Breakdown:"
        ]

        for category, value in sorted(scored_candidate.score_breakdown.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  - {category}: {value:.2f}")

        if scored_candidate.warnings:
            lines.append("Warnings:")
            for w in scored_candidate.warnings:
                lines.append(f"  - {w}")

        return "\n".join(lines)

    def compare_candidates(self, scored_candidates: List[ScoredCandidate]) -> List[Dict[str, str]]:
        comparison: List[Dict[str, str]] = []

        for i, cand in enumerate(scored_candidates):
            top_category = "none"
            if cand.score_breakdown:
                top_category = max(cand.score_breakdown.items(), key=lambda x: x[1])[0]

            comparison.append({
                "rank": str(i + 1),
                "ip": cand.ip,
                "score": f"{cand.final_score:.0%}",
                "confidence": cand.confidence_level,
                "top_category": top_category,
                "evidence_count": str(len(cand.evidence_summary)),
            })

        return comparison
