"""
Core data models for Canary findings and configuration.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


class CheckCategory(Enum):
    LOG_GAPS = "Log Gap Analysis"
    TIMESTOMPING = "Timestomping Detection"
    USN_JOURNAL = "USN Journal Tampering"
    PREFETCH = "Prefetch Anomalies"
    SYSMON = "Sysmon/Audit Gaps"
    SHELLBAGS = "Shellbag Inconsistencies"
    ANTIFORENSIC_TOOLS = "Anti-Forensic Tool Detection"
    REGISTRY = "Registry Anomalies"


MITRE_MAPPING = {
    CheckCategory.LOG_GAPS: {
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
    },
    CheckCategory.TIMESTOMPING: {
        "technique_id": "T1070.006",
        "technique_name": "Indicator Removal: Timestomp",
        "tactic": "Defense Evasion",
    },
    CheckCategory.USN_JOURNAL: {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
    },
    CheckCategory.PREFETCH: {
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
    },
    CheckCategory.SYSMON: {
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
    },
    CheckCategory.SHELLBAGS: {
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
    },
    CheckCategory.ANTIFORENSIC_TOOLS: {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
    },
    CheckCategory.REGISTRY: {
        "technique_id": "T1112",
        "technique_name": "Modify Registry",
        "tactic": "Defense Evasion",
    },
}


@dataclass
class Finding:
    """A single anti-forensic finding."""
    title: str
    description: str
    category: CheckCategory
    severity: Severity
    confidence: Confidence
    evidence: List[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    source_file: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    recommendation: str = ""
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

    def __post_init__(self):
        if self.mitre_technique is None:
            mapping = MITRE_MAPPING.get(self.category, {})
            self.mitre_technique = mapping.get("technique_id", "")
            self.mitre_tactic = mapping.get("tactic", "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_file": self.source_file,
            "recommendation": self.recommendation,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
        }


@dataclass
class ScanConfig:
    """Configuration for a Canary scan."""
    mode: str = "import"  # "live" or "import"
    evtx_paths: List[str] = field(default_factory=list)
    mft_csv_path: Optional[str] = None
    usn_csv_path: Optional[str] = None
    prefetch_csv_path: Optional[str] = None
    shimcache_csv_path: Optional[str] = None
    amcache_csv_path: Optional[str] = None
    shellbags_csv_path: Optional[str] = None
    sysmon_log_path: Optional[str] = None
    registry_hive_paths: List[str] = field(default_factory=list)
    filesystem_root: Optional[str] = None
    output_dir: str = "."
    output_format: str = "html"  # "html", "json", "both"
    verbose: bool = False
    incident_start: Optional[datetime] = None
    incident_end: Optional[datetime] = None


@dataclass
class ScanResult:
    """Aggregated results of a Canary scan."""
    findings: List[Finding] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    config: Optional[ScanConfig] = None
    checks_run: List[str] = field(default_factory=list)
    checks_skipped: List[str] = field(default_factory=list)

    @property
    def tampering_score(self) -> int:
        """Compute overall tampering score 0-100."""
        if not self.findings:
            return 0
        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        confidence_multipliers = {
            Confidence.CONFIRMED: 1.0,
            Confidence.HIGH: 0.8,
            Confidence.MEDIUM: 0.5,
            Confidence.LOW: 0.3,
            Confidence.SPECULATIVE: 0.1,
        }
        raw = sum(
            severity_weights[f.severity] * confidence_multipliers[f.confidence]
            for f in self.findings
        )
        return min(100, int(raw))

    @property
    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tampering_score": self.tampering_score,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
        }
