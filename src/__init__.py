# TrueOrigin - Origin IP Discovery Tool

from .validator import TargetValidator
from .scanner import PortScanner
from .fingerprint import Fingerprinter
from .proxy_detector import ProxyDetector
from .dns_analysis import DNSAnalyzer
from .correlator import CrossPortCorrelator
from .inference import InferenceEngine
from .scoring import ConfidenceScorer
from .output import ResultFormatter

__version__ = "1.0.0"
__all__ = [
    "TargetValidator",
    "PortScanner",
    "Fingerprinter",
    "ProxyDetector",
    "DNSAnalyzer",
    "CrossPortCorrelator",
    "InferenceEngine",
    "ConfidenceScorer",
    "ResultFormatter",
]
