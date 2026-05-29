"""
Canary Scan Engine.
Orchestrates all anti-forensic detection checks, aggregates findings, and produces results.
"""

import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Type

from canary.models import Finding, ScanConfig, ScanResult, Severity, CheckCategory
from canary.checks.base import BaseCheck
from canary.checks.log_gaps import LogGapCheck
from canary.checks.timestomping import TimestompingCheck
from canary.checks.usn_journal import UsnJournalCheck
from canary.checks.prefetch import PrefetchCheck
from canary.checks.sysmon_gaps import SysmonGapCheck
from canary.checks.shellbags import ShellbagCheck
from canary.checks.antiforensic_tools import AntiForensicToolCheck
from canary.checks.registry import RegistryCheck


# All available checks in execution order
ALL_CHECKS: List[Type[BaseCheck]] = [
    LogGapCheck,
    TimestompingCheck,
    UsnJournalCheck,
    PrefetchCheck,
    SysmonGapCheck,
    ShellbagCheck,
    AntiForensicToolCheck,
    RegistryCheck,
]


class CanaryEngine:
    """
    Core scan engine that orchestrates all anti-forensic detection checks.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._checks: List[BaseCheck] = []
        self._result: Optional[ScanResult] = None

    @property
    def result(self) -> Optional[ScanResult]:
        return self._result

    def run(self) -> ScanResult:
        """Execute all applicable checks and return aggregated results."""
        self._result = ScanResult(
            scan_start=datetime.now(),
            config=self.config,
        )

        self._print_banner()
        self._validate_config()

        # Initialize and run each check
        for check_class in ALL_CHECKS:
            check = check_class(self.config)
            self._checks.append(check)

            print(f"\n{'='*60}")
            print(f"  Running: {check.name}")
            print(f"  {check.description[:80]}...")
            print(f"{'='*60}")

            if not check.can_run():
                check.skip("Required data sources not available")

            if check.skipped:
                print(f"  ⏭ SKIPPED: {check.skip_reason}")
                self._result.checks_skipped.append(f"{check.name}: {check.skip_reason}")
                continue

            try:
                findings = check.run()
                self._result.findings.extend(findings)
                self._result.checks_run.append(check.name)

                if findings:
                    print(f"  ⚠ Found {len(findings)} issue(s):")
                    for f in findings:
                        icon = self._severity_icon(f.severity)
                        print(f"    {icon} [{f.severity.value.upper()}] {f.title}")
                else:
                    print(f"  ✓ No issues detected")

                if check.errors:
                    for err in check.errors:
                        print(f"  ⚡ Warning: {err}")

            except Exception as e:
                error_msg = f"{check.name} failed: {e}"
                self._result.checks_skipped.append(error_msg)
                print(f"  ✗ ERROR: {e}")
                if self.config.verbose:
                    import traceback
                    traceback.print_exc()

        self._result.scan_end = datetime.now()
        self._print_summary()

        return self._result

    def _print_banner(self):
        """Print the Canary banner."""
        banner = r"""
   ____
  / ___|__ _ _ __   __ _ _ __ _   _
 | |   / _` | '_ \ / _` | '__| | | |
 | |__| (_| | | | | (_| | |  | |_| |
  \____\__,_|_| |_|\__,_|_|   \__, |
                               |___/
  Anti-Forensics Detector v1.0.0
  ================================
"""
        print(banner)
        print(f"  Mode: {self.config.mode.upper()}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.config.incident_start and self.config.incident_end:
            print(f"  Incident window: {self.config.incident_start} to {self.config.incident_end}")
        print()

    def _validate_config(self):
        """Validate configuration and print data source status."""
        print("  Data Sources:")

        sources = [
            ("EVTX logs", bool(self.config.evtx_paths)),
            ("MFT CSV", bool(self.config.mft_csv_path)),
            ("USN Journal CSV", bool(self.config.usn_csv_path)),
            ("Prefetch CSV/Dir", bool(self.config.prefetch_csv_path)),
            ("Shimcache CSV", bool(self.config.shimcache_csv_path)),
            ("Amcache CSV", bool(self.config.amcache_csv_path)),
            ("Shellbags CSV", bool(self.config.shellbags_csv_path)),
            ("Sysmon log", bool(self.config.sysmon_log_path)),
            ("Registry exports", bool(self.config.registry_hive_paths)),
            ("Filesystem root", bool(self.config.filesystem_root)),
        ]

        if self.config.mode == "live":
            print("    [LIVE MODE] Scanning live system artifacts")
        else:
            for name, available in sources:
                icon = "✓" if available else "✗"
                print(f"    {icon} {name}")

        available_count = sum(1 for _, a in sources if a)
        if self.config.mode != "live" and available_count == 0:
            print("\n  ⚠ WARNING: No data sources configured. Use --help for options.")

    def _print_summary(self):
        """Print scan summary."""
        result = self._result
        duration = (result.scan_end - result.scan_start).total_seconds() if result.scan_end and result.scan_start else 0

        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Duration: {duration:.1f} seconds")
        print(f"  Checks run: {len(result.checks_run)}")
        print(f"  Checks skipped: {len(result.checks_skipped)}")
        print(f"  Total findings: {len(result.findings)}")
        print()

        # Severity breakdown
        summary = result.summary
        print(f"  Severity Breakdown:")
        print(f"    🔴 Critical: {summary.get('critical', 0)}")
        print(f"    🟠 High:     {summary.get('high', 0)}")
        print(f"    🟡 Medium:   {summary.get('medium', 0)}")
        print(f"    🔵 Low:      {summary.get('low', 0)}")
        print(f"    ⚪ Info:     {summary.get('info', 0)}")
        print()

        # Tampering score
        score = result.tampering_score
        if score >= 70:
            grade = "CRITICAL — Strong evidence of anti-forensic activity"
            color = "🔴"
        elif score >= 40:
            grade = "HIGH — Multiple indicators of evidence tampering"
            color = "🟠"
        elif score >= 20:
            grade = "MEDIUM — Some suspicious indicators found"
            color = "🟡"
        elif score > 0:
            grade = "LOW — Minor anomalies detected"
            color = "🔵"
        else:
            grade = "CLEAN — No anti-forensic indicators detected"
            color = "🟢"

        print(f"  {color} TAMPERING SCORE: {score}/100")
        print(f"  {grade}")
        print()

    @staticmethod
    def _severity_icon(severity: Severity) -> str:
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return icons.get(severity, "⚪")
