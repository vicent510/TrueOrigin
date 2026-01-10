# Advanced inference engine
# Origin validation using Host/SNI routing and response comparison.

import hashlib
import socket
import ssl
import re
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .utils import Evidence, EvidenceType, OriginCandidate, is_valid_ip, is_private_ip
from .fingerprint import Fingerprinter
from .dns_analysis import DNSAnalyzer


@dataclass
class InferenceResult:
    target: str
    techniques_applied: List[str] = field(default_factory=list)
    origin_candidates: List[OriginCandidate] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)


class InferenceEngine:
    # Advanced origin discovery using non-intrusive techniques.

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.fingerprinter = Fingerprinter(timeout=timeout)
        self.dns_analyzer = DNSAnalyzer(timeout=timeout)

    def analyze(
        self,
        target: str,
        target_ip: str,
        domain: str = None,
        existing_candidates: List[OriginCandidate] = None
    ) -> InferenceResult:

        result = InferenceResult(target=target)

        if existing_candidates:
            result.origin_candidates.extend(existing_candidates)

        self._certificate_chain_analysis(target_ip, domain, result)
        self._ip_range_inference(target_ip, result)
        self._historical_dns_inference(domain, result)
        self._infrastructure_fingerprinting(target_ip, result)

        if domain:
            self._origin_validation(domain, target_ip, result)

        self._consolidate_candidates(result)

        return result

    def _certificate_chain_analysis(
        self,
        target_ip: str,
        domain: str,
        result: InferenceResult
    ):
        result.techniques_applied.append("certificate_chain_analysis")

        for port in [443, 8443]:
            try:
                tls_info = self.fingerprinter.get_tls_info(target_ip, port)

                if not tls_info.has_tls:
                    continue

                if getattr(tls_info, "san_ips", None):
                    for ip in tls_info.san_ips:
                        if not is_private_ip(ip) and ip != target_ip:
                            candidate = OriginCandidate(
                                ip=ip,
                                confidence_score=0.6,
                                source_ports=[port],
                                reasoning="Found in certificate SAN field"
                            )
                            ev = Evidence(
                                source="Certificate SAN Analysis",
                                finding=f"IP {ip} listed in certificate SAN",
                                evidence_type=EvidenceType.STRONG,
                                raw_data={"port": port, "san_ips": tls_info.san_ips}
                            )
                            candidate.evidence.append(ev)
                            result.origin_candidates.append(candidate)
                            result.evidence.append(ev)

                if getattr(tls_info, "issuer", None) and getattr(tls_info, "subject", None):
                    if tls_info.issuer == tls_info.subject:
                        result.evidence.append(Evidence(
                            source="Certificate Analysis",
                            finding="Self-signed certificate detected (may indicate origin server)",
                            evidence_type=EvidenceType.MODERATE
                        ))

            except Exception as e:
                result.analysis_notes.append(f"Certificate analysis on port {port}: {str(e)}")

    def _ip_range_inference(self, target_ip: str, result: InferenceResult):
        result.techniques_applied.append("ip_range_inference")

        try:
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj.version == 4:
                network = ipaddress.ip_network(f"{target_ip}/24", strict=False)

                result.evidence.append(Evidence(
                    source="IP Range Analysis",
                    finding=f"Target IP in network range: {network}",
                    evidence_type=EvidenceType.WEAK,
                    raw_data={"network": str(network), "size": network.num_addresses}
                ))

                result.analysis_notes.append(
                    f"Network range {network} may contain additional infrastructure"
                )
        except ValueError:
            return

    def _historical_dns_inference(self, domain: str, result: InferenceResult):
        if not domain:
            return

        result.techniques_applied.append("historical_dns_inference")

        dns_result = self.dns_analyzer.analyze(domain)

        for candidate_ip in dns_result.origin_candidates:
            if not is_private_ip(candidate_ip):
                candidate = OriginCandidate(
                    ip=candidate_ip,
                    confidence_score=0.5,
                    reasoning="Discovered via DNS subdomain or mail server analysis"
                )

                for e in dns_result.evidence:
                    if candidate_ip in str(e.raw_data) or candidate_ip in (e.finding or ""):
                        candidate.evidence.append(e)

                result.origin_candidates.append(candidate)

        result.evidence.extend(dns_result.evidence)

    def _infrastructure_fingerprinting(self, target_ip: str, result: InferenceResult):
        result.techniques_applied.append("infrastructure_fingerprinting")

        fingerprints: Dict[int, Dict[str, object]] = {}

        for port in [80, 443, 8080]:
            try:
                use_https = port in [443, 8443]
                fp = self.fingerprinter.get_http_fingerprint(
                    target_ip, port, use_https=use_https
                )

                if getattr(fp, "server", None):
                    fingerprints[port] = {
                        "server": fp.server,
                        "response_time_ms": getattr(fp, "response_time_ms", None),
                        "headers": list(getattr(fp, "headers", {}).keys())
                    }
            except Exception:
                continue

        if fingerprints:
            result.evidence.append(Evidence(
                source="Infrastructure Fingerprint",
                finding=f"Collected fingerprints from {len(fingerprints)} port(s)",
                evidence_type=EvidenceType.MODERATE,
                raw_data=fingerprints
            ))

        for port, fp_data in fingerprints.items():
            server = str(fp_data.get("server", "")).lower()
            if server and not any(cdn in server for cdn in
                                  ["cloudflare", "akamai", "fastly", "amazon", "cloudfront"]):
                result.evidence.append(Evidence(
                    source="Server Signature",
                    finding=f"Non-CDN server signature on port {port}: {fp_data.get('server')}",
                    evidence_type=EvidenceType.MODERATE
                ))

    def _origin_validation(self, domain: str, target_ip: str, result: InferenceResult):
        # Validates candidates by comparing baseline response with direct IP access
        result.techniques_applied.append("origin_validation")

        candidate_ips: List[str] = []
        for c in result.origin_candidates:
            if c.ip and c.ip not in candidate_ips:
                candidate_ips.append(c.ip)

        try:
            dns_quick = self.dns_analyzer.quick_origin_check(domain)
            for ip in dns_quick:
                if ip not in candidate_ips and is_valid_ip(ip) and not is_private_ip(ip):
                    candidate_ips.append(ip)
                    result.origin_candidates.append(OriginCandidate(
                        ip=ip,
                        confidence_score=0.45,
                        reasoning="Discovered via quick DNS origin check"
                    ))
        except Exception:
            pass

        baseline_http = self._fetch_http_like(host=domain, port=80, use_https=False, host_header=domain, sni=None)
        baseline_https = self._fetch_http_like(host=domain, port=443, use_https=True, host_header=domain, sni=domain)

        if not baseline_http and not baseline_https:
            result.evidence.append(Evidence(
                source="Origin Validation",
                finding="Baseline requests to the domain failed; origin validation skipped",
                evidence_type=EvidenceType.WEAK
            ))
            return

        ports_to_try = [(80, False), (443, True)]

        for ip in list(candidate_ips):
            for port, use_https in ports_to_try:
                baseline = baseline_https if use_https else baseline_http
                if not baseline:
                    continue

                candidate_resp = self._fetch_http_like(
                    host=ip,
                    port=port,
                    use_https=use_https,
                    host_header=domain,
                    sni=domain if use_https else None
                )

                if not candidate_resp:
                    continue

                match_level, match_notes = self._compare_responses(baseline, candidate_resp)

                if match_level == "confirmed":
                    cand_obj = next((c for c in result.origin_candidates if c.ip == ip), None)
                    if not cand_obj:
                        cand_obj = OriginCandidate(
                            ip=ip,
                            confidence_score=0.85,
                            reasoning="Validated via Host/SNI response matching"
                        )
                        result.origin_candidates.append(cand_obj)

                    cand_obj.confidence_score = max(cand_obj.confidence_score, 0.85)

                    ev = Evidence(
                        source="Origin Validation",
                        finding=(
                            f"Content match confirmed for candidate {ip} on port {port} "
                            f"using Host/SNI routing for {domain}"
                        ),
                        evidence_type=EvidenceType.CONFIRMED,
                        raw_data={
                            "port": port,
                            "https": use_https,
                            "notes": match_notes,
                            "baseline": self._response_summary(baseline),
                            "candidate": self._response_summary(candidate_resp),
                        }
                    )
                    cand_obj.evidence.append(ev)
                    result.evidence.append(ev)

                elif match_level == "strong":
                    cand_obj = next((c for c in result.origin_candidates if c.ip == ip), None)
                    if not cand_obj:
                        cand_obj = OriginCandidate(ip=ip, confidence_score=0.55, reasoning="Strong similarity in validation checks")
                        result.origin_candidates.append(cand_obj)

                    cand_obj.confidence_score = max(cand_obj.confidence_score, 0.60)
                    ev = Evidence(
                        source="Origin Validation",
                        finding=f"Strong similarity for candidate {ip} on port {port} (not fully confirmed)",
                        evidence_type=EvidenceType.STRONG,
                        raw_data={"port": port, "https": use_https, "notes": match_notes}
                    )
                    cand_obj.evidence.append(ev)
                    result.evidence.append(ev)

        if not any(e.evidence_type == EvidenceType.CONFIRMED and e.source == "Origin Validation" for e in result.evidence):
            result.evidence.append(Evidence(
                source="Origin Validation",
                finding="No candidates produced a confirmed content match via Host/SNI validation",
                evidence_type=EvidenceType.WEAK
            ))

    def _fetch_http_like(
        self,
        host: str,
        port: int,
        use_https: bool,
        host_header: str,
        sni: Optional[str],
        path: str = "/",
        max_bytes: int = 65536
    ) -> Optional[Dict[str, object]]:

        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.settimeout(self.timeout)

            cert_subject = None
            cert_issuer = None

            if use_https:
                ctx = ssl.create_default_context()
                try:
                    tls_sock = ctx.wrap_socket(sock, server_hostname=sni or host_header)
                except ssl.SSLError:
                    ctx = ssl._create_unverified_context()
                    tls_sock = ctx.wrap_socket(sock, server_hostname=sni or host_header)

                try:
                    cert = tls_sock.getpeercert()
                    if cert:
                        subj = cert.get("subject", [])
                        iss = cert.get("issuer", [])
                        cert_subject = str(subj)[:500]
                        cert_issuer = str(iss)[:500]
                except Exception:
                    pass

                conn = tls_sock
            else:
                conn = sock

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: TrueOrigin/1.0 (authorized testing)\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            conn.sendall(req.encode("utf-8", errors="ignore"))

            data = b""
            while len(data) < max_bytes:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            try:
                conn.close()
            except Exception:
                pass

            if not data:
                return None

            header_blob, body = self._split_http(data)
            status_code = self._parse_status_code(header_blob)
            headers = self._parse_headers(header_blob)

            server = headers.get("server")
            location = headers.get("location")

            title = self._extract_title(body)
            body_hash = hashlib.sha256(body[:16384]).hexdigest() if body else None

            return {
                "status_code": status_code,
                "headers": headers,
                "server": server,
                "location": location,
                "title": title,
                "body_hash": body_hash,
                "use_https": use_https,
                "cert_subject": cert_subject,
                "cert_issuer": cert_issuer,
            }

        except Exception:
            return None

    @staticmethod
    def _split_http(raw: bytes) -> Tuple[bytes, bytes]:
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            return raw, b""
        return raw[:sep], raw[sep + 4:]

    @staticmethod
    def _parse_status_code(header_blob: bytes) -> Optional[int]:
        try:
            first_line = header_blob.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            m = re.match(r"HTTP/\d\.\d\s+(\d{3})", first_line)
            return int(m.group(1)) if m else None
        except Exception:
            return None

    @staticmethod
    def _parse_headers(header_blob: bytes) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        try:
            lines = header_blob.split(b"\r\n")[1:]
            for line in lines:
                if b":" not in line:
                    continue
                k, v = line.split(b":", 1)
                key = k.decode("iso-8859-1", errors="replace").strip().lower()
                val = v.decode("iso-8859-1", errors="replace").strip()
                if key not in headers:
                    headers[key] = val
        except Exception:
            pass
        return headers

    @staticmethod
    def _extract_title(body: bytes) -> Optional[str]:
        if not body:
            return None
        try:
            text = body[:65536].decode("utf-8", errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            if not m:
                return None
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            return title[:200] if title else None
        except Exception:
            return None

    @staticmethod
    def _response_summary(resp: Dict[str, object]) -> Dict[str, object]:
        return {
            "status_code": resp.get("status_code"),
            "server": resp.get("server"),
            "location": resp.get("location"),
            "title": resp.get("title"),
            "body_hash": resp.get("body_hash"),
            "cert_issuer": resp.get("cert_issuer"),
        }

    def _compare_responses(self, baseline: Dict[str, object], candidate: Dict[str, object]) -> Tuple[str, Dict[str, object]]:
        notes: Dict[str, object] = {}

        b_status = baseline.get("status_code")
        c_status = candidate.get("status_code")
        if b_status and c_status:
            notes["status_match"] = (b_status == c_status)
        else:
            notes["status_match"] = False

        b_hash = baseline.get("body_hash")
        c_hash = candidate.get("body_hash")
        notes["body_hash_match"] = bool(b_hash and c_hash and b_hash == c_hash)

        b_title = baseline.get("title")
        c_title = candidate.get("title")
        notes["title_match"] = bool(b_title and c_title and b_title == c_title)

        b_loc = baseline.get("location")
        c_loc = candidate.get("location")
        notes["location_match"] = bool(b_loc and c_loc and b_loc == c_loc)

        b_iss = baseline.get("cert_issuer")
        c_iss = candidate.get("cert_issuer")
        notes["cert_issuer_match"] = bool(b_iss and c_iss and b_iss == c_iss)

        if notes["body_hash_match"]:
            return "confirmed", notes

        if notes["status_match"] and notes["title_match"]:
            if baseline.get("use_https"):
                if notes["cert_issuer_match"]:
                    return "confirmed", notes
                return "strong", notes

            return "strong", notes

        if notes["status_match"] and (notes["title_match"] or notes["location_match"]):
            return "strong", notes

        return "no_match", notes

    def _consolidate_candidates(self, result: InferenceResult):
        consolidated: Dict[str, OriginCandidate] = {}

        for candidate in result.origin_candidates:
            ip = candidate.ip
            if not ip or not is_valid_ip(ip) or is_private_ip(ip):
                continue

            if ip in consolidated:
                existing = consolidated[ip]
                existing.confidence_score = max(existing.confidence_score, candidate.confidence_score)
                existing.evidence.extend(candidate.evidence)
                existing.source_ports.extend(candidate.source_ports)
                if candidate.reasoning and candidate.reasoning not in (existing.reasoning or ""):
                    existing.reasoning = (existing.reasoning + "; " + candidate.reasoning).strip("; ")
            else:
                consolidated[ip] = candidate

        for c in consolidated.values():
            c.source_ports = sorted(list(set(c.source_ports)))

        result.origin_candidates = sorted(
            consolidated.values(),
            key=lambda c: c.confidence_score,
            reverse=True
        )

    def quick_inference(self, domain: str) -> List[str]:
        candidates: List[str] = []
        dns_candidates = self.dns_analyzer.quick_origin_check(domain)
        for ip in dns_candidates:
            if is_valid_ip(ip) and not is_private_ip(ip):
                candidates.append(ip)
        return list(set(candidates))
