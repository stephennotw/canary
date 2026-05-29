"""
Base class for all Canary anti-forensic checks.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from canary.models import Finding, ScanConfig, CheckCategory


class BaseCheck(ABC):
    """Abstract base class for all anti-forensic detection checks."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._findings: List[Finding] = []
        self._errors: List[str] = []
        self._skipped: bool = False
        self._skip_reason: str = ""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this check."""
        pass

    @property
    @abstractmethod
    def category(self) -> CheckCategory:
        """The check category."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what this check detects."""
        pass

    @property
    def findings(self) -> List[Finding]:
        return self._findings

    @property
    def errors(self) -> List[str]:
        return self._errors

    @property
    def skipped(self) -> bool:
        return self._skipped

    @property
    def skip_reason(self) -> str:
        return self._skip_reason

    def skip(self, reason: str):
        """Mark this check as skipped."""
        self._skipped = True
        self._skip_reason = reason

    def add_finding(self, finding: Finding):
        """Add a finding to results."""
        self._findings.append(finding)

    def add_error(self, error: str):
        """Record a non-fatal error during checking."""
        self._errors.append(error)

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute the check and return findings."""
        pass

    def can_run(self) -> bool:
        """Check if required data sources are available."""
        return True

    def log(self, message: str):
        """Log a message if verbose mode is on."""
        if self.config.verbose:
            print(f"  [{self.name}] {message}")
