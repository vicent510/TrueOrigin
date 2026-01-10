#!/usr/bin/env python3
# TrueOrigin - Origin IP Discovery Tool
# For authorized security testing only.

import argparse
import sys
import logging
from typing import Dict, List

from src.validator import TargetValidator
from src.scanner import PortScanner
from src.proxy_detector import ProxyDetector
from src.dns_analysis import DNSAnalyzer
from src.correlator import CrossPortCorrelator
from src.inference import InferenceEngine
from src.scoring import ConfidenceScorer
from src.output import ResultFormatter
from src.utils import (
    Evidence,
    OriginCandidate,
    setup_logging,
    enrich_candidate_with_rdap,
    merge_evidence,
)


class TrueOrigin:
    # Main orchestrator for the analysis pipeline.

    def __init__(self, timeout: float = 5.0, verbose: bool = False):
        self.timeout = timeout
        self.logger = setup_logging(verbose)
        self.verbose = verbose

        self.validator = TargetValidator(timeout=timeout)
        self.scanner = PortScanner(timeout=timeout)
        self.proxy_detector = ProxyDetector(timeout=timeout)
        self.dns_analyzer = DNSAnalyzer(timeout=timeout)
        self.correlator = CrossPortCorrelator()
        self.inference = InferenceEngine(timeout=timeout)
        self.scorer = ConfidenceScorer()
        self.formatter = ResultFormatter(use_colors=True)

    @staticmethod
    def _dedupe_candidates(candidates: List[OriginCandidate]) -> List[OriginCandidate]:
        # Deduplicate by IP and merge evidence
        by_ip: Dict[str, OriginCandidate] = {}
        for c in candidates:
            if c.ip not in by_ip:
                by_ip[c.ip] = c
                continue

            existing = by_ip[c.ip]
            existing.confidence_score = max(existing.confidence_score, c.confidence_score)

            if not existing.reasoning and c.reasoning:
                existing.reasoning = c.reasoning

            if c.source_ports:
                existing.source_ports = sorted(list(set(existing.source_ports + c.source_ports)))

            existing.evidence = merge_evidence(existing.evidence, c.evidence)

            for attr in ("asn", "org", "network_name", "country", "provider_hint"):
                val = getattr(existing, attr, None)
                new_val = getattr(c, attr, None)
                if not val and new_val:
                    setattr(existing, attr, new_val)

            existing.is_cdn_edge = bool(getattr(existing, "is_cdn_edge", False) or getattr(c, "is_cdn_edge", False))

        return list(by_ip.values())

    def analyze(
        self,
        target: str,
        extended_scan: bool = False,
        skip_inference: bool = False,
        output_json: bool = False
    ) -> int:
        # Run the full analysis pipeline
        all_evidence: List[Evidence] = []
        all_candidates: List[OriginCandidate] = []

        if not output_json:
            print(self.formatter.format_banner())

        # Phase 1: Validation
        self.logger.info(f"Validating target: {target}")
        validation = self.validator.validate(target)
        all_evidence.extend(validation.evidence)

        if not validation.is_valid:
            if not output_json:
                print(self.formatter.format_validation_result(
                    False, False, target, None, validation.error_message
                ))
            self.logger.error(f"Invalid target: {validation.error_message}")
            return 1

        if not validation.is_reachable:
            if not output_json:
                print(self.formatter.format_validation_result(
                    True, False, target, validation.target_ip, validation.error_message
                ))
            self.logger.error("Target is not reachable")
            return 1

        target_ip = validation.target_ip
        domain = target if validation.target_type == "domain" else None

        if not output_json:
            print(self.formatter.format_validation_result(
                True, True, target, target_ip
            ))

        # Phase 2: Port scan
        self.logger.info("Scanning for open ports...")
        if not output_json:
            print(f"\n[*] Scanning ports on {target_ip}...")

        def progress_callback(scanned: int, total: int):
            if not output_json and self.verbose:
                print(f"\r    Progress: {scanned}/{total} ports", end="", flush=True)

        scan_result = self.scanner.scan(
            target_ip,
            extended=extended_scan,
            progress_callback=progress_callback if self.verbose else None
        )

        if self.verbose and not output_json:
            print()

        all_evidence.extend(scan_result.scan_evidence)

        if not scan_result.open_ports:
            if not output_json:
                print(self.formatter.format_port_scan([]))
            self.logger.warning("No open ports found")
            return 0

        if not output_json:
            print(self.formatter.format_port_scan(scan_result.open_ports))

        # Phase 3: Proxy detection
        self.logger.info("Analyzing proxy/CDN presence...")
        if not output_json:
            print(f"\n[*] Detecting proxies on {len(scan_result.open_ports)} open port(s)...")

        proxy_results = self.proxy_detector.detect_all_ports(
            target_ip, scan_result.open_ports
        )

        for _, result in proxy_results.items():
            all_evidence.extend(result.evidence)

        proxied_ports = self.proxy_detector.get_proxied_ports(proxy_results)
        non_proxied_ports = self.proxy_detector.get_non_proxied_ports(proxy_results)

        providers: Dict[str, List[int]] = {}
        for port, provider, _conf in proxied_ports:
            providers.setdefault(provider, []).append(port)

        if not output_json:
            print(self.formatter.format_proxy_analysis(
                [p[0] for p in proxied_ports],
                non_proxied_ports,
                providers
            ))

        # Phase 4: Cross-port correlation
        self.logger.info("Correlating findings across ports...")
        correlation = self.correlator.correlate(
            target_ip, scan_result.open_ports, proxy_results
        )
        all_evidence.extend(correlation.evidence)
        all_candidates.extend(correlation.origin_candidates)

        # Phase 5: DNS analysis
        if domain:
            self.logger.info("Performing DNS analysis...")
            if not output_json:
                print(f"\n[*] Analyzing DNS records for {domain}...")

            dns_result = self.dns_analyzer.analyze(domain, target_ip)
            all_evidence.extend(dns_result.evidence)

            for ip in dns_result.origin_candidates:
                candidate = OriginCandidate(
                    ip=ip,
                    confidence_score=0.5,
                    reasoning="Discovered via DNS analysis"
                )
                all_candidates.append(candidate)

        # Phase 6: Advanced inference
        if not skip_inference and not non_proxied_ports:
            self.logger.info("Applying advanced inference techniques...")
            if not output_json:
                print("\n[*] Running advanced inference analysis...")

            inference_result = self.inference.analyze(
                target, target_ip, domain, all_candidates
            )
            all_evidence.extend(inference_result.evidence)
            all_candidates = inference_result.origin_candidates

        all_candidates = self._dedupe_candidates(all_candidates)

        # Phase 7: RDAP enrichment
        self.logger.info("Enriching candidates with IP intelligence (RDAP)...")
        for candidate in all_candidates:
            rdap_evidence = enrich_candidate_with_rdap(candidate, timeout=self.timeout)
            if rdap_evidence:
                candidate.evidence = merge_evidence(candidate.evidence, rdap_evidence)
                all_evidence.extend(rdap_evidence)

        # Phase 8: Attach evidence to candidates
        for candidate in all_candidates:
            if not candidate.evidence:
                candidate.evidence = []

            for e in all_evidence:
                if candidate.ip in (e.finding or "") or candidate.ip in str(e.raw_data):
                    candidate.evidence.append(e)

        # Phase 9: Scoring
        self.logger.info("Scoring origin candidates...")
        scored_candidates = self.scorer.score_candidates(all_candidates)

        # Phase 10: Output
        if output_json:
            print(self.formatter.to_json(
                target, target_ip, scan_result.open_ports,
                scored_candidates, all_evidence
            ))
        else:
            print(self.formatter.format_origin_candidates(scored_candidates, target_ip))
            print(self.formatter.format_evidence_chain(all_evidence))
            print(self.formatter.format_recommendations(
                scored_candidates, bool(non_proxied_ports)
            ))
            print(self.formatter.format_disclaimer())

        return 0


def main():
    parser = argparse.ArgumentParser(
        description="TrueOrigin - Origin IP Discovery & Proxy Analysis Tool",
        epilog="For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "target",
        help="Target domain or IP address to analyze"
    )

    parser.add_argument(
        "-e", "--extended",
        action="store_true",
        help="Use extended port scan (more ports, slower)"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--skip-inference",
        action="store_true",
        help="Skip advanced inference phase"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    if not args.json:
        print("\n" + "=" * 60)
        print("  AUTHORIZED USE ONLY")
        print("  This tool is for security testing on systems you own or")
        print("  have explicit written permission to test.")
        print("=" * 60 + "\n")

    try:
        tool = TrueOrigin(timeout=args.timeout, verbose=args.verbose)

        if args.no_color:
            tool.formatter.use_colors = False

        exit_code = tool.analyze(
            args.target,
            extended_scan=args.extended,
            skip_inference=args.skip_inference,
            output_json=args.json
        )

        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
