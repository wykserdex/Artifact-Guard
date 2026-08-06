"""Passive analysis modules."""

from analysis.passive.dns import DnsAnalyzer, resolve_dns
from analysis.passive.rdap import RdapAnalyzer, lookup_rdap
from analysis.passive.homoglyphs import HomoglyphAnalyzer, detect_homoglyphs
from analysis.passive.reputation import ReputationAnalyzer

__all__ = [
    "DnsAnalyzer",
    "RdapAnalyzer",
    "HomoglyphAnalyzer",
    "ReputationAnalyzer",
    "resolve_dns",
    "lookup_rdap",
    "detect_homoglyphs",
]
