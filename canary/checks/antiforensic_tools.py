"""
Anti-Forensic Tool Detection Check.
Detects artifacts of known anti-forensic tools across multiple evidence sources:
- Prefetch entries for wiping/cleaning tools
- Shimcache/Amcache evidence of anti-forensic tool execution
- File system artifacts (SDelete patterns, CCleaner registry keys)
- Known anti-forensic tool file signatures
"""

import os
import re
from datetime import datetime
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
from canary.parsers.shimcache_parser import ShimcacheParser, ShimcacheEntry
from canary.parsers.amcache_parser import AmcacheParser, AmcacheEntry

# Comprehensive anti-forensic tool database
# Format: {executable_name_upper: (description, severity, category)}
TOOL_DATABASE = {
    # === Secure Deletion / Wiping ===
    "SDELETE.EXE": ("Sysinternals SDelete - Secure file/disk wiping", Severity.CRITICAL, "wiping"),
    "SDELETE64.EXE": ("Sysinternals SDelete 64-bit", Severity.CRITICAL, "wiping"),
    "ERASER.EXE": ("Eraser - Secure file/folder deletion", Severity.HIGH, "wiping"),
    "ERASERD.EXE": ("Eraser daemon service", Severity.HIGH, "wiping"),
    "BCWIPE.EXE": ("BCWipe - Military-grade secure deletion", Severity.CRITICAL, "wiping"),
    "DBAN.EXE": ("DBAN - Disk sanitization", Severity.CRITICAL, "wiping"),
    "WIPE.EXE": ("Generic file wiping tool", Severity.HIGH, "wiping"),
    "SHRED.EXE": ("File shredding tool", Severity.HIGH, "wiping"),
    "FILESHREDDER.EXE": ("File Shredder application", Severity.HIGH, "wiping"),
    "HDSHREDDER.EXE": ("Hard Disk Shredder", Severity.CRITICAL, "wiping"),

    # === System Cleaners (commonly misused) ===
    "CCLEANER.EXE": ("CCleaner - System cleaner (clears browser history, logs, temp)", Severity.HIGH, "cleaning"),
    "CCLEANER64.EXE": ("CCleaner 64-bit", Severity.HIGH, "cleaning"),
    "CCLEANERPORTABLE.EXE": ("CCleaner Portable (no install = more suspicious)", Severity.HIGH, "cleaning"),
    "BLEACHBIT.EXE": ("BleachBit - Open-source system cleaner", Severity.HIGH, "cleaning"),
    "PRIVAZER.EXE": ("PrivaZer - Privacy-focused cleaner", Severity.HIGH, "cleaning"),
    "CLEANMGR.EXE": ("Windows Disk Cleanup", Severity.LOW, "cleaning"),

    # === Timestamp Manipulation ===
    "TIMESTOMP.EXE": ("Timestomp - Direct timestamp manipulation", Severity.CRITICAL, "timestomping"),
    "NTTIMETOOLS.EXE": ("NTTimeTools - NTFS timestamp editor", Severity.CRITICAL, "timestomping"),
    "SETMACE.EXE": ("SetMACE - Timestamp modification tool", Severity.CRITICAL, "timestomping"),
    "BULKFILECHANGER.EXE": ("BulkFileChanger - Mass timestamp editor", Severity.HIGH, "timestomping"),
    "ATTRIBUTECHANGER.EXE": ("Attribute Changer - File metadata editor", Severity.MEDIUM, "timestomping"),

    # === Log Manipulation ===
    "WEVTUTIL.EXE": ("Windows Event Log utility (can clear/export logs)", Severity.MEDIUM, "log_manipulation"),
    "CLEAREV.EXE": ("Meterpreter clearev equivalent", Severity.CRITICAL, "log_manipulation"),
    "EVENTCLEANER.EXE": ("Event log cleaner", Severity.CRITICAL, "log_manipulation"),
    "PHANT0M.EXE": ("Phant0m - Kills Event Log service threads", Severity.CRITICAL, "log_manipulation"),

    # === Disk/Partition Tools (suspicious context) ===
    "DISKPART.EXE": ("Windows DiskPart (can wipe volumes)", Severity.MEDIUM, "disk_tools"),

    # === Credential Theft ===
    "MIMIKATZ.EXE": ("Mimikatz - Credential dumping", Severity.CRITICAL, "credential_theft"),
    "PROCDUMP.EXE": ("ProcDump - Process memory dumper (LSASS dumping)", Severity.HIGH, "credential_theft"),
    "PROCDUMP64.EXE": ("ProcDump 64-bit", Severity.HIGH, "credential_theft"),
    "LAZAGNE.EXE": ("LaZagne - Multi-platform credential harvester", Severity.CRITICAL, "credential_theft"),
    "SECRETSDUMP.EXE": ("Impacket secretsdump", Severity.CRITICAL, "credential_theft"),
    "LSASSY.EXE": ("Lsassy - LSASS credential extractor", Severity.CRITICAL, "credential_theft"),
    "NANODUMP.EXE": ("Nanodump - LSASS minidump", Severity.CRITICAL, "credential_theft"),
    "PYPYKATZ.EXE": ("Pypykatz - Python mimikatz", Severity.CRITICAL, "credential_theft"),

    # === Lateral Movement ===
    "PSEXEC.EXE": ("PsExec - Remote execution", Severity.HIGH, "lateral_movement"),
    "PSEXEC64.EXE": ("PsExec 64-bit", Severity.HIGH, "lateral_movement"),
    "PSEXESVC.EXE": ("PsExec service component (was deployed here)", Severity.CRITICAL, "lateral_movement"),
    "PAEXEC.EXE": ("PAExec - PsExec alternative", Severity.HIGH, "lateral_movement"),
    "WMIEXEC.EXE": ("Impacket WMIExec", Severity.HIGH, "lateral_movement"),
    "SMBEXEC.EXE": ("Impacket SMBExec", Severity.HIGH, "lateral_movement"),
    "ATEXEC.EXE": ("Impacket AtExec", Severity.HIGH, "lateral_movement"),
    "EVIL-WINRM.EXE": ("Evil-WinRM - WinRM shell", Severity.CRITICAL, "lateral_movement"),

    # === Reconnaissance ===
    "SHARPHOUND.EXE": ("SharpHound - BloodHound AD collector", Severity.CRITICAL, "recon"),
    "BLOODHOUND.EXE": ("BloodHound", Severity.CRITICAL, "recon"),
    "ADEXPLORER.EXE": ("AD Explorer - Active Directory browser", Severity.MEDIUM, "recon"),
    "NMAP.EXE": ("Nmap - Network scanner", Severity.HIGH, "recon"),
    "NBTSCAN.EXE": ("NBTScan - NetBIOS scanner", Severity.HIGH, "recon"),
    "ADVANCED_PORT_SCANNER.EXE": ("Advanced Port Scanner", Severity.HIGH, "recon"),
    "SOFTPERFECT_NETSCAN.EXE": ("SoftPerfect Network Scanner", Severity.HIGH, "recon"),
    "ANGRYIPSCAN.EXE": ("Angry IP Scanner", Severity.MEDIUM, "recon"),

    # === Privilege Escalation ===
    "RUBEUS.EXE": ("Rubeus - Kerberos abuse tool", Severity.CRITICAL, "privesc"),
    "SEATBELT.EXE": ("Seatbelt - Security audit tool (used for privesc recon)", Severity.HIGH, "privesc"),
    "WINPEAS.EXE": ("WinPEAS - Windows Privilege Escalation scanner", Severity.CRITICAL, "privesc"),
    "SHARPUP.EXE": ("SharpUp - Privilege escalation checker", Severity.HIGH, "privesc"),
    "JUICYPOTATO.EXE": ("JuicyPotato - Token impersonation privesc", Severity.CRITICAL, "privesc"),
    "PRINTSPOOFER.EXE": ("PrintSpoofer - Privilege escalation", Severity.CRITICAL, "privesc"),
    "GODPOTATO.EXE": ("GodPotato - Privilege escalation", Severity.CRITICAL, "privesc"),

    # === Data Exfiltration ===
    "RCLONE.EXE": ("Rclone - Cloud sync (common exfil tool)", Severity.HIGH, "exfiltration"),
    "MEGASYNC.EXE": ("MegaSync - MEGA cloud sync", Severity.HIGH, "exfiltration"),
    "MEGACMD.EXE": ("MegaCMD - MEGA command line", Severity.HIGH, "exfiltration"),
    "FILEZILLA.EXE": ("FileZilla - FTP client", Severity.LOW, "exfiltration"),
    "WINSCP.EXE": ("WinSCP - SFTP/SCP client", Severity.LOW, "exfiltration"),
    "7Z.EXE": ("7-Zip CLI (used for staging compressed archives)", Severity.LOW, "exfiltration"),
    "7ZA.EXE": ("7-Zip standalone", Severity.LOW, "exfiltration"),
    "RAR.EXE": ("WinRAR CLI", Severity.LOW, "exfiltration"),

    # === Defense Evasion ===
    "PROCESSHACKER.EXE": ("Process Hacker - Can kill security processes", Severity.HIGH, "evasion"),
    "PCHUNTER.EXE": ("PCHunter - Kernel-level process tool", Severity.HIGH, "evasion"),
    "GMER.EXE": ("GMER - Rootkit detector (also used to find/kill AV)", Severity.MEDIUM, "evasion"),
    "RKILL.EXE": ("RKill - Kills running malware processes", Severity.MEDIUM, "evasion"),
}

# SDelete creates files with pattern like AAAAAAA.AAA, BBBBBBB.BBB etc
SDELETE_PATTERN = re.compile(r'^([A-Z])\1{5,}\.[A-Z]{3}$', re.IGNORECASE)

# CCleaner registry artifacts
CCLEANER_REGISTRY_KEYS = [
    r"Software\Piriform\CCleaner",
    r"Software\Piriform\CCleaner\(default)",
]


class AntiForensicToolCheck(BaseCheck):
    """Detects artifacts of known anti-forensic and attacker tools."""

    @property
    def name(self) -> str:
        return "Anti-Forensic Tool Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.ANTIFORENSIC_TOOLS

    @property
    def description(self) -> str:
        return (
            "Scans Prefetch, Shimcache, Amcache, and filesystem for evidence of "
            "known anti-forensic tools, attacker utilities, and their artifacts. "
            "Detects tools even after they've been uninstalled or deleted."
        )

    def can_run(self) -> bool:
        return bool(
            self.config.prefetch_csv_path
            or self.config.shimcache_csv_path
            or self.config.amcache_csv_path
            or self.config.mode == "live"
        )

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No execution artifact data sources configured")
            return []

        # Collect tool detections from all sources
        all_detections: Dict[str, List[Tuple[str, str, Optional[datetime]]]] = {}
        # key=exe_name, value=list of (source, detail, timestamp)

        self._scan_prefetch(all_detections)
        self._scan_shimcache(all_detections)
        self._scan_amcache(all_detections)
        self._check_sdelete_artifacts(all_detections)

        if not all_detections:
            self.log("No anti-forensic tool artifacts detected")
            return self._findings

        # Group by category and severity
        self._generate_findings(all_detections)

        return self._findings

    def _scan_prefetch(self, detections: Dict):
        """Scan Prefetch for known tool execution."""
        if not self.config.prefetch_csv_path and self.config.mode != "live":
            return

        parser = PrefetchParser()
        try:
            if self.config.mode == "live":
                pf_dir = r"C:\Windows\Prefetch"
                if os.path.isdir(pf_dir):
                    parser.parse(pf_dir)
            else:
                parser.parse(self.config.prefetch_csv_path)
        except Exception as e:
            self.add_error(f"Failed to parse Prefetch: {e}")
            return

        for entry in parser.entries:
            exe_upper = entry.executable_name.upper()
            if exe_upper in TOOL_DATABASE:
                detections.setdefault(exe_upper, []).append((
                    "Prefetch",
                    f"Run count: {entry.run_count}, "
                    f"Last runs: {', '.join(t.strftime('%Y-%m-%d %H:%M') for t in entry.last_run_times[:3])}",
                    entry.latest_run,
                ))

    def _scan_shimcache(self, detections: Dict):
        """Scan Shimcache for known tool execution."""
        if not self.config.shimcache_csv_path:
            return

        parser = ShimcacheParser()
        try:
            parser.parse(self.config.shimcache_csv_path)
        except Exception as e:
            self.add_error(f"Failed to parse Shimcache: {e}")
            return

        for entry in parser.entries:
            exe_upper = os.path.basename(entry.path).upper()
            if exe_upper in TOOL_DATABASE:
                detections.setdefault(exe_upper, []).append((
                    "Shimcache",
                    f"Path: {entry.path}, Modified: {entry.last_modified}",
                    entry.last_modified,
                ))

    def _scan_amcache(self, detections: Dict):
        """Scan Amcache for known tool execution."""
        if not self.config.amcache_csv_path:
            return

        parser = AmcacheParser()
        try:
            parser.parse(self.config.amcache_csv_path)
        except Exception as e:
            self.add_error(f"Failed to parse Amcache: {e}")
            return

        for entry in parser.entries:
            exe_upper = (entry.filename or os.path.basename(entry.full_path or "")).upper()
            if exe_upper in TOOL_DATABASE:
                sha1_info = f", SHA1: {entry.sha1}" if entry.sha1 else ""
                detections.setdefault(exe_upper, []).append((
                    "Amcache",
                    f"Path: {entry.full_path}{sha1_info}, "
                    f"Publisher: {entry.publisher or 'Unknown'}",
                    entry.last_modified or entry.created,
                ))

    def _check_sdelete_artifacts(self, detections: Dict):
        """Check for SDelete file artifacts (characteristic renamed files)."""
        if not self.config.filesystem_root:
            return

        # SDelete creates temporary files with repeating character names
        # e.g., AAAAAA.AAA, BBBBBB.BBB during secure deletion
        sdelete_artifacts = []

        try:
            for root, dirs, files in os.walk(self.config.filesystem_root):
                for fname in files:
                    if SDELETE_PATTERN.match(fname):
                        fpath = os.path.join(root, fname)
                        sdelete_artifacts.append(fpath)
                # Don't recurse too deep
                if root.count(os.sep) > 5:
                    dirs.clear()
        except (PermissionError, OSError):
            pass

        if sdelete_artifacts:
            detections.setdefault("SDELETE.EXE", []).append((
                "Filesystem",
                f"SDelete file artifacts found: {len(sdelete_artifacts)} files "
                f"(e.g., {os.path.basename(sdelete_artifacts[0])})",
                None,
            ))

    def _generate_findings(self, detections: Dict[str, List[Tuple[str, str, Optional[datetime]]]]):
        """Generate findings grouped by tool category."""
        # Group by category
        categories: Dict[str, List[Tuple[str, str, Severity, List]]] = {}

        for exe_name, sources in detections.items():
            if exe_name not in TOOL_DATABASE:
                continue
            desc, severity, category = TOOL_DATABASE[exe_name]
            categories.setdefault(category, []).append((exe_name, desc, severity, sources))

        category_labels = {
            "wiping": "Secure Deletion / Wiping Tools",
            "cleaning": "System Cleaners",
            "timestomping": "Timestamp Manipulation Tools",
            "log_manipulation": "Log Manipulation Tools",
            "disk_tools": "Disk/Partition Tools",
            "credential_theft": "Credential Theft Tools",
            "lateral_movement": "Lateral Movement Tools",
            "recon": "Reconnaissance Tools",
            "privesc": "Privilege Escalation Tools",
            "exfiltration": "Data Exfiltration Tools",
            "evasion": "Defense Evasion Tools",
        }

        for category, tools in categories.items():
            max_severity = max(t[2] for t in tools)
            label = category_labels.get(category, category.title())

            evidence = [f"Category: {label}", f"Tools detected: {len(tools)}", ""]

            earliest_ts = None
            for exe_name, desc, severity, sources in tools:
                evidence.append(f"  [{severity.value.upper()}] {exe_name}: {desc}")
                for source, detail, ts in sources:
                    evidence.append(f"    Source: {source} — {detail}")
                    if ts and (earliest_ts is None or ts < earliest_ts):
                        earliest_ts = ts

            # Determine confidence based on number of corroborating sources
            all_source_types = set()
            for _, _, _, sources in tools:
                for source, _, _ in sources:
                    all_source_types.add(source)

            if len(all_source_types) >= 2:
                confidence = Confidence.CONFIRMED
            else:
                confidence = Confidence.HIGH

            self.add_finding(Finding(
                title=f"{label} Detected ({len(tools)} tool(s))",
                description=(
                    f"Detected execution artifacts for {len(tools)} {label.lower()} tool(s) "
                    f"across {len(all_source_types)} evidence source(s) ({', '.join(sorted(all_source_types))}). "
                    f"These tools are associated with anti-forensic activity and/or active attack operations."
                ),
                category=self.category,
                severity=max_severity,
                confidence=confidence,
                evidence=evidence,
                timestamp=earliest_ts,
                recommendation=(
                    f"Investigate each tool's execution timeline and correlate with the incident. "
                    f"For wiping/cleaning tools, determine what data was destroyed. "
                    f"For attack tools, determine what assets were compromised."
                ),
            ))
