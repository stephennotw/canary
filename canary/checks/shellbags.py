"""
Shellbag Inconsistency Detection Check.
Detects:
- Shellbag entries for paths that no longer exist on the filesystem
- Shellbag entries for paths in unusual/suspicious locations
- Evidence of accessed directories that were later cleaned up
- External device access patterns from shellbags
"""

import os
import csv
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


class ShellbagEntry:
    """Represents a parsed shellbag record."""

    __slots__ = [
        "path",
        "last_write",
        "first_explored",
        "last_explored",
        "mft_entry",
        "mft_sequence",
        "slot",
        "registry_key",
        "absolute_path",
    ]

    def __init__(self):
        self.path: str = ""
        self.last_write: Optional[datetime] = None
        self.first_explored: Optional[datetime] = None
        self.last_explored: Optional[datetime] = None
        self.mft_entry: int = 0
        self.mft_sequence: int = 0
        self.slot: str = ""
        self.registry_key: str = ""
        self.absolute_path: str = ""

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "absolute_path": self.absolute_path,
            "last_write": self.last_write.isoformat() if self.last_write else None,
            "first_explored": self.first_explored.isoformat() if self.first_explored else None,
            "last_explored": self.last_explored.isoformat() if self.last_explored else None,
        }


# Suspicious directory patterns
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "\\perflogs\\",
    "\\recycler\\",
    "$recycle.bin",
    "\\windows\\temp\\",
    "\\public\\",
    "\\users\\public\\",
]

# External device indicators in shellbag paths
EXTERNAL_DEVICE_PATTERNS = [
    "removable disk",
    "usb",
    "external",
    ":\\",  # Drive letters beyond C: often indicate removable media
]

# Known staging directories used by attackers
STAGING_PATHS = [
    "\\perflogs\\",
    "\\intel\\",
    "\\dell\\",
    "\\hp\\",
    "\\music\\",
    "\\videos\\",
    "\\contacts\\",
    "\\links\\",
    "\\saved games\\",
    "\\searches\\",
    "\\3d objects\\",
]


class ShellbagCheck(BaseCheck):
    """Detects shellbag entries that indicate deleted or suspicious directory access."""

    @property
    def name(self) -> str:
        return "Shellbag Inconsistency Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.SHELLBAGS

    @property
    def description(self) -> str:
        return (
            "Analyzes Windows Shellbag artifacts for folder navigation history "
            "that contradicts the current filesystem state. Shellbags persist "
            "even after folders are deleted, revealing directories the attacker accessed."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.shellbags_csv_path)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No shellbag data source configured")
            return []

        entries = []
        if self.config.mode == "live":
            self.add_error(
                "Live shellbag parsing requires registry hive access. "
                "Use SBECmd to export shellbags to CSV first."
            )
            return []
        else:
            try:
                entries = self._parse_shellbag_csv(self.config.shellbags_csv_path)
                self.log(f"Parsed shellbags: {len(entries)} entries")
            except Exception as e:
                self.add_error(f"Failed to parse shellbags: {e}")
                return []

        if not entries:
            self.skip("No shellbag entries found")
            return []

        # Run checks
        self._check_ghost_directories(entries)
        self._check_suspicious_paths(entries)
        self._check_staging_directories(entries)
        self._check_external_devices(entries)
        self._check_temp_directory_access(entries)

        return self._findings

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str or ts_str.strip() == "":
            return None
        ts_str = ts_str.strip()
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str[:26].rstrip("Z"), fmt)
            except ValueError:
                continue
        return None

    def _parse_shellbag_csv(self, path: str) -> List[ShellbagEntry]:
        """Parse SBECmd CSV output."""
        entries = []
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = ShellbagEntry()

                    entry.absolute_path = row.get("AbsolutePath", row.get("Path",
                                          row.get("absolute_path", row.get("Value", ""))))
                    entry.path = entry.absolute_path

                    entry.last_write = self._parse_timestamp(
                        row.get("LastWriteTime", row.get("LastWrite",
                        row.get("last_write", ""))))
                    entry.first_explored = self._parse_timestamp(
                        row.get("FirstExplored", row.get("first_explored", "")))
                    entry.last_explored = self._parse_timestamp(
                        row.get("LastExplored", row.get("last_explored", "")))

                    mft_str = row.get("MFTEntry", row.get("mft_entry", "0"))
                    entry.mft_entry = int(mft_str) if mft_str and mft_str.isdigit() else 0

                    seq_str = row.get("MFTSequenceNumber", row.get("mft_sequence", "0"))
                    entry.mft_sequence = int(seq_str) if seq_str and seq_str.isdigit() else 0

                    entry.registry_key = row.get("RegistryKey", row.get("registry_key", ""))

                    if entry.absolute_path:
                        entries.append(entry)
                except (ValueError, KeyError):
                    continue
        return entries

    def _check_ghost_directories(self, entries: List[ShellbagEntry]):
        """
        Find shellbag entries for directories that no longer exist.
        If we have a filesystem root to check against, verify path existence.
        """
        if not self.config.filesystem_root:
            return

        ghost_dirs = []
        fs_root = self.config.filesystem_root

        for entry in entries:
            path = entry.absolute_path
            if not path or len(path) < 4:
                continue

            # Construct full path relative to filesystem root
            if path.startswith("\\"):
                full_path = os.path.join(fs_root, path.lstrip("\\"))
            elif len(path) > 2 and path[1] == ":":
                # Drive letter path - map to filesystem root
                rel_path = path[3:] if len(path) > 3 else ""
                full_path = os.path.join(fs_root, rel_path)
            else:
                continue

            if not os.path.exists(full_path):
                ghost_dirs.append(entry)

        if not ghost_dirs:
            return

        evidence = [
            f"Shellbag entries for non-existent directories: {len(ghost_dirs)}",
            f"Filesystem root checked: {fs_root}",
            "",
        ]

        for entry in ghost_dirs[:20]:
            ts_info = ""
            if entry.last_explored:
                ts_info = f" (last explored: {entry.last_explored})"
            elif entry.last_write:
                ts_info = f" (last write: {entry.last_write})"
            evidence.append(f"  {entry.absolute_path}{ts_info}")

        severity = Severity.MEDIUM
        if len(ghost_dirs) > 10:
            severity = Severity.HIGH

        self.add_finding(Finding(
            title="Ghost Directories: Shellbag Entries for Deleted Paths",
            description=(
                f"Found {len(ghost_dirs)} shellbag entries pointing to directories that "
                f"no longer exist on the filesystem. Shellbags persist after folder deletion, "
                f"revealing directories that a user navigated to before they were cleaned up. "
                f"This is evidence of activity the user or attacker tried to hide."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence=evidence,
            timestamp=ghost_dirs[0].last_explored or ghost_dirs[0].last_write,
            recommendation=(
                "These paths represent directories that were accessed and then deleted. "
                "Cross-reference with USN Journal for deletion timestamps. "
                "Attempt file carving in these directory locations."
            ),
        ))

    def _check_suspicious_paths(self, entries: List[ShellbagEntry]):
        """Flag shellbag entries for inherently suspicious paths."""
        suspicious = []

        for entry in entries:
            path_lower = entry.absolute_path.lower()
            for pattern in SUSPICIOUS_PATHS:
                if pattern in path_lower:
                    suspicious.append((entry, pattern))
                    break

        if not suspicious:
            return

        # Only flag if there's a meaningful number
        if len(suspicious) < 3:
            return

        evidence = [f"Shellbag entries for suspicious locations: {len(suspicious)}", ""]
        for entry, pattern in suspicious[:15]:
            ts = entry.last_explored or entry.last_write
            evidence.append(
                f"  {entry.absolute_path} (pattern: {pattern})"
                f"{f' at {ts}' if ts else ''}"
            )

        self.add_finding(Finding(
            title="User Navigation to Suspicious Directories",
            description=(
                f"Shellbags show the user navigated to {len(suspicious)} directories in "
                f"suspicious locations (temp folders, recycler, public shares, etc.). "
                f"These locations are commonly used by attackers for staging, tool storage, "
                f"and temporary file operations."
            ),
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=evidence,
            recommendation=(
                "Review the specific paths accessed. Check if these directories currently "
                "contain any files and cross-reference access times with known incident timeline."
            ),
        ))

    def _check_staging_directories(self, entries: List[ShellbagEntry]):
        """Detect access to known attacker staging directories."""
        staging = []

        for entry in entries:
            path_lower = entry.absolute_path.lower()
            for pattern in STAGING_PATHS:
                if pattern in path_lower:
                    # Only flag if the path has subdirectories (attacker-created)
                    # Simple heuristic: path is deeper than just the pattern
                    remaining = path_lower.split(pattern)[-1]
                    if remaining and remaining != "\\":
                        staging.append((entry, pattern))
                        break

        if not staging:
            return

        evidence = [f"Potential staging directory access: {len(staging)}", ""]
        for entry, pattern in staging[:10]:
            ts = entry.last_explored or entry.last_write
            evidence.append(
                f"  {entry.absolute_path}"
                f"{f' at {ts}' if ts else ''}"
            )

        self.add_finding(Finding(
            title="Potential Staging Directory Access Detected",
            description=(
                f"Shellbags reveal access to {len(staging)} directories in locations "
                f"commonly used by attackers for staging tools and exfiltrated data "
                f"(PerfLogs, Intel, Dell, rarely-used user profile folders). "
                f"These directories are chosen because they blend with legitimate system paths."
            ),
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=evidence,
            recommendation=(
                "Check if these directories still exist and contain any files. "
                "Examine USN Journal for file creation/deletion activity in these paths."
            ),
        ))

    def _check_external_devices(self, entries: List[ShellbagEntry]):
        """Detect evidence of external device (USB) access."""
        external = []

        for entry in entries:
            path_lower = entry.absolute_path.lower()

            # Check for non-C: drive letters (potential removable media)
            if len(path_lower) > 2 and path_lower[1] == ":" and path_lower[0] not in ("c", "\\"):
                external.append(entry)
                continue

            for pattern in EXTERNAL_DEVICE_PATTERNS:
                if pattern in path_lower:
                    external.append(entry)
                    break

        if not external:
            return

        # Group by drive letter or device
        drives: Dict[str, List[ShellbagEntry]] = {}
        for entry in external:
            drive = entry.absolute_path[:2] if len(entry.absolute_path) > 2 else "Unknown"
            drives.setdefault(drive, []).append(entry)

        evidence = [
            f"External device/drive access detected: {len(external)} entries",
            f"Unique drives: {', '.join(sorted(drives.keys()))}",
            "",
        ]
        for drive, drive_entries in sorted(drives.items()):
            evidence.append(f"  Drive {drive} ({len(drive_entries)} paths):")
            for entry in drive_entries[:5]:
                ts = entry.last_explored or entry.last_write
                evidence.append(f"    {entry.absolute_path}{f' at {ts}' if ts else ''}")

        self.add_finding(Finding(
            title="External Device/Drive Access Detected in Shellbags",
            description=(
                f"Shellbags reveal access to {len(external)} paths on non-C: drives or "
                f"removable media. This may indicate data staging on external devices, "
                f"tool deployment from USB, or data exfiltration via removable media."
            ),
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=evidence,
            recommendation=(
                "Identify the external devices from USB device logs (Event ID 6416, "
                "USBSTOR registry keys). Determine what data was accessed on these devices "
                "and whether the devices are still available for analysis."
            ),
        ))

    def _check_temp_directory_access(self, entries: List[ShellbagEntry]):
        """Detect unusual depth of navigation into temp directories."""
        deep_temp = []

        for entry in entries:
            path_lower = entry.absolute_path.lower()
            if "\\temp\\" not in path_lower and "\\tmp\\" not in path_lower:
                continue

            # Count path depth after temp
            temp_idx = max(path_lower.find("\\temp\\"), path_lower.find("\\tmp\\"))
            if temp_idx < 0:
                continue

            after_temp = entry.absolute_path[temp_idx + 5:]  # +5 for \temp
            depth = after_temp.count("\\")

            if depth >= 2:  # 2+ levels deep in temp = suspicious
                deep_temp.append((entry, depth))

        if not deep_temp:
            return

        evidence = [
            f"Deep temp directory navigation: {len(deep_temp)} entries",
            "",
        ]
        for entry, depth in sorted(deep_temp, key=lambda x: x[1], reverse=True)[:10]:
            ts = entry.last_explored or entry.last_write
            evidence.append(
                f"  {entry.absolute_path} (depth: {depth})"
                f"{f' at {ts}' if ts else ''}"
            )

        self.add_finding(Finding(
            title="Deep Navigation Into Temp Directories",
            description=(
                f"Shellbags show navigation {len(deep_temp)} time(s) into nested subdirectories "
                f"within temp folders. Users rarely browse deep into temp directories — this "
                f"pattern is typical of attackers navigating to their tool staging locations."
            ),
            category=self.category,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            evidence=evidence,
            recommendation=(
                "Review these specific paths for any remaining files. "
                "Cross-reference with Prefetch and execution artifacts."
            ),
        ))
