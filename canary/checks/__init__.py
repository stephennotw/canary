"""
Anti-forensic detection checks.
Each check module analyzes specific artifact types for evidence of tampering.
"""

from canary.checks.log_gaps import LogGapCheck
from canary.checks.timestomping import TimestompingCheck
from canary.checks.usn_journal import UsnJournalCheck
from canary.checks.prefetch import PrefetchCheck
from canary.checks.sysmon_gaps import SysmonGapCheck
from canary.checks.shellbags import ShellbagCheck
from canary.checks.antiforensic_tools import AntiForensicToolCheck
from canary.checks.registry import RegistryCheck

__all__ = [
    "LogGapCheck",
    "TimestompingCheck",
    "UsnJournalCheck",
    "PrefetchCheck",
    "SysmonGapCheck",
    "ShellbagCheck",
    "AntiForensicToolCheck",
    "RegistryCheck",
]
