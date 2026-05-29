"""
Prefetch Anomaly Detection Check.
Detects:
- Expected prefetch files missing for programs with execution evidence elsewhere
- Prefetch timestamps inconsistent with other execution artifacts
- Prefetch files for known anti-forensic tools
- Missing prefetch for critical system processes (Prefetch disabled?)
"""

import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from canary.checks.base import BaseCheck
from canary.models import (
    CheckCategory,
    Confidence,
    Finding,
    ScanConfig,
    Severity,
)
from canary.parsers.prefetch_parser import PrefetchParser, PrefetchEntry
from canary.parsers.shimcache_parser import ShimcacheParser
from canary.parsers.amcache_parser import AmcacheParser

# Programs that SHOULD always have prefetch on an active system
EXPECTED_PREFETCH = {
    "SVCHOST.EXE",
    "EXPLORER.EXE",
    "CMD.EXE",
    "DLLHOST.EXE",
    "TASKHOSTW.EXE",
}

# Known anti-forensic / attacker tools
ANTIFORENSIC_EXECUTABLES = {
    "SDELETE.EXE": "Sysinternals SDelete - Secure file deletion",
    "SDELETE64.EXE": "Sysinternals SDelete 64-bit",
    "CIPHER.EXE": "Windows cipher /w - Wipe free space",
    "CCLEANER.EXE": "CCleaner - System cleaner (often used for anti-forensics)",
    "CCLEANER64.EXE": "CCleaner 64-bit",
    "BLEACHBIT.EXE": "BleachBit - Open-source system cleaner",
    "ERASER.EXE": "Eraser - Secure file deletion",
    "BCWIPE.EXE": "BCWipe - Secure wiping tool",
    "WEVTUTIL.EXE": "Windows Event Log utility (can clear logs)",
    "TIMESTOMP.EXE": "Timestomping tool",
    "WIPE.EXE": "Generic file wiping tool",
    "SHRED.EXE": "File shredding tool",
    "PSEXEC.EXE": "PsExec - Remote execution (lateral movement)",
    "PSEXEC64.EXE": "PsExec 64-bit",
    "MIMIKATZ.EXE": "Mimikatz - Credential dumping",
    "PROCDUMP.EXE": "ProcDump - Process dumper (can dump LSASS)",
    "PROCDUMP64.EXE": "ProcDump 64-bit",
    "RCLONE.EXE": "Rclone - Cloud sync (used for data exfiltration)",
    "MEGASYNC.EXE": "MegaSync - Cloud sync (used for data exfiltration)",
    "7Z.EXE": "7-Zip (used for staging/exfil compression)",
    "7ZA.EXE": "7-Zip standalone",
    "RAR.EXE": "WinRAR (used for staging/exfil compression)",
    "NMAP.EXE": "Nmap - Network scanner",
    "ADVANCED_PORT_SCANNER.EXE": "Advanced Port Scanner",
    "NBTSCAN.EXE": "NetBIOS scanner",
    "SHARPHOUND.EXE": "SharpHound - BloodHound collector",
    "RUBEUS.EXE": "Rubeus - Kerberos abuse tool",
    "CERTUTIL.EXE": "CertUtil (LOLBin - used for download/decode)",
    "MSHTA.EXE": "MSHTA (LOLBin - script execution)",
    "REGSVR32.EXE": "Regsvr32 (LOLBin - proxy execution)",
    "RUNDLL32.EXE": "Rundll32 (LOLBin - proxy execution)",
    "WSCRIPT.EXE": "Windows Script Host",
    "CSCRIPT.EXE": "Console Script Host",
    "MSBUILD.EXE": "MSBuild (LOLBin - code execution)",
    "INSTALLUTIL.EXE": "InstallUtil (LOLBin - code execution)",
    "POWERSHELL.EXE": "PowerShell",
    "PWSH.EXE": "PowerShell Core",
}

# Timestamp tolerance for cross-referencing
TIMESTAMP_TOLERANCE = timedelta(days=7)


class PrefetchCheck(BaseCheck):
    """Detects Prefetch anomalies indicative of anti-forensic activity."""

    @property
    def name(self) -> str:
        return "Prefetch Anomaly Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.PREFETCH

    @property
    def description(self) -> str:
        return (
            "Analyzes Windows Prefetch files for missing expected entries, "
            "anti-forensic tool execution evidence, and timestamp inconsistencies "
            "when cross-referenced with Shimcache and Amcache."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.prefetch_csv_path)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No Prefetch data source configured")
            return []

        pf_parser = PrefetchParser()

        if self.config.mode == "live":
            pf_dir = r"C:\Windows\Prefetch"
            if os.path.isdir(pf_dir):
                try:
                    pf_parser.parse(pf_dir)
                except Exception as e:
                    self.add_error(f"Failed to parse Prefetch directory: {e}")
            else:
                self.skip("Prefetch directory not found (may be disabled)")
                return []
        else:
            try:
                pf_parser.parse(self.config.prefetch_csv_path)
                self.log(f"Parsed Prefetch: {pf_parser.entry_count} entries")
            except Exception as e:
                self.add_error(f"Failed to parse Prefetch: {e}")
                return []

        if not pf_parser.entries:
            self._check_prefetch_disabled()
            return self._findings

        # Load cross-reference sources
        shimcache_paths = set()
        amcache_paths = set()

        if self.config.shimcache_csv_path:
            try:
                sc_parser = ShimcacheParser()
                sc_parser.parse(self.config.shimcache_csv_path)
                shimcache_paths = set(
                    os.path.basename(e.path).upper()
                    for e in sc_parser.entries if e.path
                )
                self.log(f"Loaded Shimcache: {sc_parser.entry_count} entries")
            except Exception as e:
                self.add_error(f"Failed to load Shimcache: {e}")

        if self.config.amcache_csv_path:
            try:
                ac_parser = AmcacheParser()
                ac_parser.parse(self.config.amcache_csv_path)
                amcache_paths = set(
                    os.path.basename(e.full_path).upper()
                    for e in ac_parser.entries if e.full_path
                )
                self.log(f"Loaded Amcache: {ac_parser.entry_count} entries")
            except Exception as e:
                self.add_error(f"Failed to load Amcache: {e}")

        # Run checks
        self._check_antiforensic_tools(pf_parser.entries)
        self._check_missing_prefetch(pf_parser.entries, shimcache_paths, amcache_paths)
        self._check_prefetch_density(pf_parser.entries)
        self._check_execution_evidence_gaps(pf_parser.entries, shimcache_paths, amcache_paths)

        return self._findings

    def _check_prefetch_disabled(self):
        """Flag if Prefetch appears to be disabled."""
        self.add_finding(Finding(
            title="Windows Prefetch May Be Disabled",
            description=(
                "No Prefetch entries were found. Windows Prefetch tracks program execution "
                "history and is enabled by default. If Prefetch is disabled, it could be "
                "an anti-forensic measure to prevent execution tracking."
            ),
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=[
                "No Prefetch entries loaded from any source",
                "Prefetch is normally enabled on Windows client systems",
                "Check registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
                "\\Memory Management\\PrefetchParameters\\EnablePrefetcher",
            ],
            recommendation=(
                "Verify the EnablePrefetcher registry value. Value 0 = disabled. "
                "On server SKUs, Prefetch may be legitimately disabled."
            ),
        ))

    def _check_antiforensic_tools(self, entries: List[PrefetchEntry]):
        """Detect Prefetch entries for known anti-forensic and attacker tools."""
        found_tools = []

        for entry in entries:
            exe_upper = entry.executable_name.upper()
            if exe_upper in ANTIFORENSIC_EXECUTABLES:
                found_tools.append((entry, ANTIFORENSIC_EXECUTABLES[exe_upper]))

        if not found_tools:
            return

        # Categorize by severity
        critical_tools = {
            "SDELETE.EXE", "SDELETE64.EXE", "MIMIKATZ.EXE",
            "TIMESTOMP.EXE", "WIPE.EXE", "SHRED.EXE",
            "SHARPHOUND.EXE", "RUBEUS.EXE",
        }
        high_tools = {
            "CCLEANER.EXE", "CCLEANER64.EXE", "BLEACHBIT.EXE",
            "ERASER.EXE", "BCWIPE.EXE", "PSEXEC.EXE", "PSEXEC64.EXE",
            "PROCDUMP.EXE", "PROCDUMP64.EXE", "RCLONE.EXE",
        }

        has_critical = any(e.executable_name.upper() in critical_tools for e, _ in found_tools)
        has_high = any(e.executable_name.upper() in high_tools for e, _ in found_tools)

        severity = Severity.CRITICAL if has_critical else (Severity.HIGH if has_high else Severity.MEDIUM)

        evidence = [f"Anti-forensic/attacker tools found in Prefetch: {len(found_tools)}", ""]
        for entry, description in found_tools:
            run_times = ", ".join(t.strftime("%Y-%m-%d %H:%M:%S") for t in entry.last_run_times[:3])
            evidence.append(
                f"  {entry.executable_name}: {description}"
            )
            evidence.append(
                f"    Run count: {entry.run_count}, Last runs: {run_times or 'Unknown'}"
            )

        self.add_finding(Finding(
            title="Anti-Forensic / Attacker Tool Execution Detected",
            description=(
                f"Prefetch records show execution of {len(found_tools)} known anti-forensic "
                f"or attacker tools. These tools are commonly used for evidence destruction, "
                f"credential theft, lateral movement, or data exfiltration."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            timestamp=found_tools[0][0].latest_run,
            recommendation=(
                "Investigate each tool's execution context: when was it run, by whom, "
                "and what was the system state at that time. Cross-reference with "
                "event logs and Sysmon for command-line arguments."
            ),
        ))

    def _check_missing_prefetch(
        self,
        entries: List[PrefetchEntry],
        shimcache_paths: Set[str],
        amcache_paths: Set[str],
    ):
        """Detect programs with execution evidence in Shimcache/Amcache but missing from Prefetch."""
        prefetch_names = set(e.executable_name.upper() for e in entries)

        # Programs in other artifacts but NOT in Prefetch
        other_evidence = shimcache_paths | amcache_paths
        missing_from_prefetch = []

        for exe in other_evidence:
            if not exe:
                continue
            # Only flag executables (not DLLs etc)
            if not exe.endswith(".EXE"):
                continue
            if exe not in prefetch_names:
                in_shimcache = exe in shimcache_paths
                in_amcache = exe in amcache_paths
                missing_from_prefetch.append((exe, in_shimcache, in_amcache))

        # Filter: only flag suspicious ones (anti-forensic tools or system tools)
        suspicious_missing = [
            (exe, sc, ac) for exe, sc, ac in missing_from_prefetch
            if exe in ANTIFORENSIC_EXECUTABLES
        ]

        if suspicious_missing:
            evidence = [
                f"Suspicious executables with Shimcache/Amcache evidence but NO Prefetch: {len(suspicious_missing)}",
                "",
            ]
            for exe, in_sc, in_ac in suspicious_missing:
                sources = []
                if in_sc:
                    sources.append("Shimcache")
                if in_ac:
                    sources.append("Amcache")
                desc = ANTIFORENSIC_EXECUTABLES.get(exe, "")
                evidence.append(f"  {exe}: found in {', '.join(sources)} — {desc}")

            self.add_finding(Finding(
                title="Suspicious Executables Missing from Prefetch",
                description=(
                    f"Found {len(suspicious_missing)} suspicious executables that have execution "
                    f"evidence in Shimcache/Amcache but are MISSING from Prefetch. This suggests "
                    f"that Prefetch files were selectively deleted to hide execution evidence."
                ),
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=evidence,
                recommendation=(
                    "The absence of Prefetch for these tools, combined with their presence in "
                    "Shimcache/Amcache, confirms they ran but someone deleted the Prefetch evidence. "
                    "Check the USN Journal for .pf file deletion events."
                ),
            ))

    def _check_prefetch_density(self, entries: List[PrefetchEntry]):
        """Check if Prefetch directory has abnormally few entries."""
        # Windows typically has 128-1024 Prefetch files on an active system
        if len(entries) < 20:
            self.add_finding(Finding(
                title="Abnormally Low Prefetch Count",
                description=(
                    f"Only {len(entries)} Prefetch entries found. An active Windows system "
                    f"typically has 100+ Prefetch files (up to 1024 on Win 8+). A very low "
                    f"count suggests bulk deletion of Prefetch files."
                ),
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[
                    f"Prefetch entries found: {len(entries)}",
                    "Expected: 100-1024 for active system",
                    "Prefetch limit: 1024 (Win 8+) or 128 (Win 7)",
                ],
                recommendation=(
                    "Check USN Journal for bulk .pf file deletion. "
                    "Check if the Prefetch directory was cleared as part of "
                    "anti-forensic cleanup."
                ),
            ))

    def _check_execution_evidence_gaps(
        self,
        pf_entries: List[PrefetchEntry],
        shimcache_paths: Set[str],
        amcache_paths: Set[str],
    ):
        """Check for expected system Prefetch entries being missing."""
        prefetch_names = set(e.executable_name.upper() for e in pf_entries)

        missing_expected = []
        for exe in EXPECTED_PREFETCH:
            if exe not in prefetch_names:
                missing_expected.append(exe)

        if missing_expected and len(pf_entries) > 10:
            # Only flag if we have a reasonable Prefetch set but core entries are missing
            self.add_finding(Finding(
                title="Core System Prefetch Files Missing",
                description=(
                    f"Expected Prefetch entries for core system processes are missing: "
                    f"{', '.join(missing_expected)}. These processes run on every Windows "
                    f"system and should always have Prefetch files unless they were deleted."
                ),
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[
                    f"Missing core Prefetch: {', '.join(missing_expected)}",
                    f"Total Prefetch entries present: {len(pf_entries)}",
                ],
                recommendation=(
                    "Core system Prefetch files should always be present. Their absence "
                    "suggests Prefetch directory manipulation."
                ),
            ))
