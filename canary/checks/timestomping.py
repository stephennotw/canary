"""
Timestomping Detection Check.
Detects:
- $STANDARD_INFORMATION vs $FILE_NAME timestamp mismatches in MFT
- Impossible timestamps (modified before created)
- $SI timestamps earlier than $FN timestamps (classic timestomping indicator)
- Timestamps with suspicious nanosecond precision (all zeros = tool-modified)
- Clusters of files with identical timestamps (batch timestomping)
"""

from collections import Counter, defaultdict
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
from canary.parsers.mft_parser import MftParser, MftEntry

# Threshold: if $SI created is more than this before $FN created, flag it
SI_FN_THRESHOLD = timedelta(hours=1)

# Threshold for "impossible" timestamp (modified significantly before created)
IMPOSSIBLE_THRESHOLD = timedelta(seconds=2)

# Minimum cluster size for batch timestomping detection
MIN_CLUSTER_SIZE = 5

# Suspicious extensions (more likely targets of timestomping)
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".hta", ".scr", ".pif", ".com", ".msi", ".cpl",
}


class TimestompingCheck(BaseCheck):
    """Detects evidence of timestamp manipulation in NTFS MFT."""

    @property
    def name(self) -> str:
        return "Timestomping Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.TIMESTOMPING

    @property
    def description(self) -> str:
        return (
            "Compares $STANDARD_INFORMATION and $FILE_NAME timestamps in MFT records "
            "to detect timestomping. $FN timestamps can only be modified by the kernel, "
            "making them reliable reference points."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.mft_csv_path)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No MFT data source configured")
            return []

        parser = MftParser()

        if self.config.mode == "live":
            self._load_live_mft(parser)
        else:
            try:
                parser.parse(self.config.mft_csv_path)
                self.log(f"Parsed MFT: {parser.entry_count} entries")
            except Exception as e:
                self.add_error(f"Failed to parse MFT: {e}")
                return []

        if not parser.entries:
            self.skip("No MFT entries found to analyze")
            return []

        self.log(f"Analyzing {parser.entry_count} MFT entries")

        # Run detection checks
        self._check_si_fn_mismatch(parser.entries)
        self._check_impossible_timestamps(parser.entries)
        self._check_zero_nanoseconds(parser.entries)
        self._check_batch_timestomping(parser.entries)
        self._check_si_before_fn(parser.entries)
        self._check_future_timestamps(parser.entries)

        return self._findings

    def _load_live_mft(self, parser: MftParser):
        """Attempt to parse MFT from live system."""
        # Live MFT parsing requires raw disk access (admin)
        self.add_error(
            "Live MFT parsing requires raw disk access. "
            "Use MFTECmd to export MFT to CSV first, then use --mft-csv option."
        )

    def _check_si_fn_mismatch(self, entries: List[MftEntry]):
        """
        Detect entries where $SI created is significantly different from $FN created.
        When timestomping tools modify timestamps, they only modify $SI.
        $FN timestamps are kernel-managed and preserve the real creation time.
        """
        mismatches = []

        for entry in entries:
            if not (entry.si_created and entry.fn_created):
                continue

            diff = abs(entry.si_created - entry.fn_created)
            if diff > SI_FN_THRESHOLD:
                # Calculate which is earlier
                si_earlier = entry.si_created < entry.fn_created
                mismatches.append((entry, diff, si_earlier))

        if not mismatches:
            return

        # Sort by magnitude of difference
        mismatches.sort(key=lambda x: x[1], reverse=True)

        # Determine severity
        critical_mismatches = [m for m in mismatches if m[2]]  # $SI before $FN
        exe_mismatches = [
            m for m in mismatches
            if any(m[0].filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        ]

        if critical_mismatches:
            severity = Severity.CRITICAL
            confidence = Confidence.CONFIRMED
        elif exe_mismatches:
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        elif len(mismatches) > 20:
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        else:
            severity = Severity.MEDIUM
            confidence = Confidence.HIGH

        evidence = [
            f"Total entries with $SI/$FN mismatch: {len(mismatches)}",
            f"Entries where $SI < $FN (classic timestomping): {len(critical_mismatches)}",
            f"Executable files affected: {len(exe_mismatches)}",
            "",
            "Top mismatches (by time difference):",
        ]

        for entry, diff, si_earlier in mismatches[:15]:
            marker = " [TIMESTOMPED]" if si_earlier else ""
            evidence.append(
                f"  {entry.full_path or entry.filename}: "
                f"$SI={entry.si_created}, $FN={entry.fn_created}, "
                f"diff={diff}{marker}"
            )

        self.add_finding(Finding(
            title="$SI/$FN Timestamp Mismatch Detected (Timestomping)",
            description=(
                f"Found {len(mismatches)} MFT entries where $STANDARD_INFORMATION timestamps "
                f"significantly differ from $FILE_NAME timestamps. "
                f"{len(critical_mismatches)} entries have $SI created BEFORE $FN created, "
                f"which is physically impossible without deliberate modification and is a "
                f"confirmed indicator of timestomping."
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "The $FN timestamps represent the true file creation time. Use $FN timestamps "
                "for timeline analysis instead of $SI. Focus on executable files and files in "
                "user-writable directories. Correlate with USN Journal for additional context."
            ),
        ))

    def _check_impossible_timestamps(self, entries: List[MftEntry]):
        """Detect files where modified time is before created time."""
        impossible = []

        for entry in entries:
            if not (entry.si_created and entry.si_modified):
                continue

            if entry.si_modified < entry.si_created - IMPOSSIBLE_THRESHOLD:
                impossible.append(entry)

        if not impossible:
            return

        severity = Severity.HIGH if len(impossible) > 5 else Severity.MEDIUM
        confidence = Confidence.CONFIRMED

        evidence = [
            f"Files with modified < created: {len(impossible)}",
            "",
        ]
        for entry in impossible[:15]:
            evidence.append(
                f"  {entry.full_path or entry.filename}: "
                f"created={entry.si_created}, modified={entry.si_modified}"
            )

        self.add_finding(Finding(
            title="Impossible Timestamps: Modified Before Created",
            description=(
                f"Found {len(impossible)} files where the last modified timestamp is BEFORE "
                f"the creation timestamp. This is physically impossible under normal operation "
                f"and indicates deliberate timestamp manipulation."
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "These files have been timestomped. Cross-reference with $FN timestamps "
                "and USN Journal to determine actual file creation and modification times."
            ),
        ))

    def _check_zero_nanoseconds(self, entries: List[MftEntry]):
        """
        Detect timestamps with zero sub-second precision.
        NTFS stores timestamps with 100ns precision. Real timestamps almost always
        have non-zero sub-second components. Timestomping tools often set timestamps
        with zero nanoseconds (e.g., exactly 2023-01-15 08:00:00.0000000).
        """
        zero_ns_entries = []

        for entry in entries:
            if not entry.si_created:
                continue
            # Check if all $SI timestamps have zero microseconds
            si_times = [entry.si_created, entry.si_modified, entry.si_accessed]
            si_times = [t for t in si_times if t]

            if not si_times:
                continue

            all_zero = all(t.microsecond == 0 for t in si_times)
            if all_zero and len(si_times) >= 2:
                # Check $FN timestamps for comparison
                fn_times = [entry.fn_created, entry.fn_modified, entry.fn_accessed]
                fn_times = [t for t in fn_times if t]
                fn_has_precision = any(t.microsecond != 0 for t in fn_times)

                if fn_has_precision:
                    zero_ns_entries.append(entry)

        if not zero_ns_entries:
            return

        if len(zero_ns_entries) < 3:
            return  # Could be coincidence

        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM

        if len(zero_ns_entries) > 20:
            severity = Severity.HIGH
            confidence = Confidence.HIGH

        evidence = [
            f"Files with zero-precision $SI timestamps (but non-zero $FN): {len(zero_ns_entries)}",
            "",
        ]
        for entry in zero_ns_entries[:10]:
            evidence.append(
                f"  {entry.full_path or entry.filename}: "
                f"$SI created={entry.si_created} (zero μs), "
                f"$FN created={entry.fn_created}"
            )

        self.add_finding(Finding(
            title="Suspicious Zero-Precision Timestamps",
            description=(
                f"Found {len(zero_ns_entries)} files where all $SI timestamps have zero "
                f"sub-second precision while $FN timestamps have normal precision. "
                f"NTFS stores timestamps with 100ns precision, so real timestamps almost "
                f"always have non-zero sub-second values. This pattern is typical of "
                f"timestomping tools that set whole-second timestamps."
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "Review these files for other signs of manipulation. "
                "The zero-precision pattern suggests use of a timestomping tool "
                "that doesn't replicate nanosecond-level detail."
            ),
        ))

    def _check_batch_timestomping(self, entries: List[MftEntry]):
        """
        Detect clusters of files with identical $SI timestamps.
        When attackers batch-timestomp files, they often set the same target timestamp.
        """
        # Group by $SI created timestamp (rounded to second)
        ts_groups: Dict[str, List[MftEntry]] = defaultdict(list)

        for entry in entries:
            if not entry.si_created:
                continue
            # Round to second for grouping
            ts_key = entry.si_created.strftime("%Y-%m-%d %H:%M:%S")
            ts_groups[ts_key].append(entry)

        # Find clusters of identical timestamps
        clusters = [
            (ts, group) for ts, group in ts_groups.items()
            if len(group) >= MIN_CLUSTER_SIZE
        ]

        if not clusters:
            return

        # Filter out known legitimate clusters (Windows updates, installs)
        suspicious_clusters = []
        for ts, group in clusters:
            # Check if files are in diverse directories (suspicious)
            dirs = set()
            for entry in group:
                path = entry.full_path or entry.filename
                parent = path.rsplit("\\", 1)[0] if "\\" in path else ""
                dirs.add(parent.lower())

            # If files span multiple directories, more suspicious
            if len(dirs) > 2:
                suspicious_clusters.append((ts, group, dirs))
            # If they're executables
            elif any(
                entry.filename.lower().endswith(ext)
                for entry in group
                for ext in SUSPICIOUS_EXTENSIONS
            ):
                suspicious_clusters.append((ts, group, dirs))

        if not suspicious_clusters:
            return

        evidence = [f"Suspicious timestamp clusters found: {len(suspicious_clusters)}", ""]

        for ts, group, dirs in suspicious_clusters[:5]:
            evidence.append(f"Timestamp: {ts} ({len(group)} files in {len(dirs)} directories)")
            for entry in group[:5]:
                evidence.append(f"    {entry.full_path or entry.filename}")
            if len(group) > 5:
                evidence.append(f"    ... and {len(group) - 5} more")

        self.add_finding(Finding(
            title="Batch Timestomping: Files with Identical Timestamps",
            description=(
                f"Found {len(suspicious_clusters)} cluster(s) of files sharing the exact same "
                f"$SI creation timestamp across multiple directories. This pattern is characteristic "
                f"of batch timestomping where an attacker sets the same target timestamp on many files."
            ),
            category=self.category,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=evidence,
            recommendation=(
                "Examine $FN timestamps for these files to determine their real creation times. "
                "The shared timestamp is the target the attacker chose — it may correspond to "
                "a legitimate system file's timestamp that was copied."
            ),
        ))

    def _check_si_before_fn(self, entries: List[MftEntry]):
        """
        Specifically check for $SI created < $FN created.
        This is THE definitive timestomping indicator: it's physically impossible
        for $SI to be earlier than $FN without direct manipulation because $FN
        is set by the kernel at file creation and $SI is initially set to the same value.
        """
        definitive = []

        for entry in entries:
            if not (entry.si_created and entry.fn_created):
                continue
            if entry.si_created < entry.fn_created - timedelta(seconds=2):
                definitive.append(entry)

        if not definitive:
            return

        # This is already partially covered by si_fn_mismatch, but we add a
        # separate high-confidence finding for the definitive cases
        exe_files = [
            e for e in definitive
            if any(e.filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        ]

        if exe_files:
            evidence = [
                f"Executable files with definitive timestomping: {len(exe_files)}",
                "",
            ]
            for entry in exe_files[:10]:
                diff = entry.fn_created - entry.si_created
                evidence.append(
                    f"  {entry.full_path or entry.filename}: "
                    f"$SI={entry.si_created}, $FN={entry.fn_created}, "
                    f"backdated by {diff}"
                )

            self.add_finding(Finding(
                title="CONFIRMED Timestomping on Executable Files",
                description=(
                    f"Found {len(exe_files)} executable files where $SI created is BEFORE "
                    f"$FN created. This is physically impossible without deliberate manipulation. "
                    f"The attacker backdated these files to avoid timeline-based detection."
                ),
                category=self.category,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                recommendation=(
                    "These are confirmed timestomped executables. The $FN created timestamp "
                    "represents the TRUE creation time. Collect and analyze these files — "
                    "they are likely malicious. The target timestamps chosen may reveal "
                    "the attacker's intent (e.g., matching legitimate OS file dates)."
                ),
            ))

    def _check_future_timestamps(self, entries: List[MftEntry]):
        """Detect files with timestamps in the future."""
        now = datetime.now()
        future_threshold = now + timedelta(days=1)

        future_entries = []
        for entry in entries:
            for ts in [entry.si_created, entry.si_modified, entry.fn_created, entry.fn_modified]:
                if ts and ts > future_threshold:
                    future_entries.append((entry, ts))
                    break

        if not future_entries:
            return

        evidence = [f"Files with future timestamps: {len(future_entries)}", ""]
        for entry, ts in future_entries[:10]:
            evidence.append(f"  {entry.full_path or entry.filename}: {ts}")

        self.add_finding(Finding(
            title="Files with Future Timestamps",
            description=(
                f"Found {len(future_entries)} files with timestamps set in the future "
                f"(beyond {future_threshold.strftime('%Y-%m-%d')}). This indicates either "
                f"clock manipulation or deliberate timestomping with a future date."
            ),
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence=evidence,
            recommendation="Check system clock sync history. Review these files for signs of tampering.",
        ))
