"""
USN Journal Tampering Detection Check.
Detects:
- Truncated USN journals (smaller than expected for disk age)
- Orphaned USN entries referencing MFT records that don't exist
- Gaps in USN sequence numbers
- Abnormal deletion patterns (bulk deletions in short windows)
- Journal size anomalies
"""

import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from canary.checks.base import BaseCheck
from canary.models import (
    CheckCategory,
    Confidence,
    Finding,
    ScanConfig,
    Severity,
)
from canary.parsers.usn_parser import UsnParser, UsnRecord
from canary.parsers.mft_parser import MftParser, MftEntry


# Minimum expected USN journal entries per day for an active system
MIN_USN_ENTRIES_PER_DAY = 500

# Threshold for bulk deletion detection (files deleted within N minutes)
BULK_DELETE_WINDOW_MINUTES = 5
BULK_DELETE_MIN_COUNT = 20

# Maximum percentage of orphaned entries before flagging
MAX_ORPHAN_PERCENTAGE = 15.0


class UsnJournalCheck(BaseCheck):
    """Detects evidence of USN Journal manipulation and tampering."""

    @property
    def name(self) -> str:
        return "USN Journal Analyzer"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.USN_JOURNAL

    @property
    def description(self) -> str:
        return (
            "Analyzes the NTFS USN Journal ($UsnJrnl) for signs of tampering, "
            "including truncation, orphaned references, sequence gaps, and "
            "suspicious bulk deletion patterns."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.usn_csv_path)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No USN Journal data source configured")
            return []

        usn_parser = UsnParser()

        if self.config.mode == "live":
            self.add_error(
                "Live USN Journal parsing requires raw disk access. "
                "Use MFTECmd to export $J to CSV first."
            )
            return []

        try:
            usn_parser.parse(self.config.usn_csv_path)
            self.log(f"Parsed USN Journal: {usn_parser.record_count} records")
        except Exception as e:
            self.add_error(f"Failed to parse USN Journal: {e}")
            return []

        if not usn_parser.records:
            self.skip("No USN Journal records found")
            return []

        # Load MFT if available for cross-referencing
        mft_parser = None
        if self.config.mft_csv_path:
            try:
                mft_parser = MftParser()
                mft_parser.parse(self.config.mft_csv_path)
                self.log(f"Loaded MFT for cross-reference: {mft_parser.entry_count} entries")
            except Exception as e:
                self.add_error(f"Failed to load MFT for cross-reference: {e}")

        # Run checks
        self._check_journal_truncation(usn_parser.records)
        self._check_usn_gaps(usn_parser.records)
        self._check_bulk_deletions(usn_parser.records)
        self._check_orphaned_references(usn_parser.records, mft_parser)
        self._check_journal_clearing_artifacts(usn_parser.records)
        self._check_anti_forensic_deletions(usn_parser.records)

        return self._findings

    def _check_journal_truncation(self, records: List[UsnRecord]):
        """Check if USN journal appears truncated (too few entries for time span)."""
        ts_records = [r for r in records if r.timestamp]
        if len(ts_records) < 2:
            return

        ts_records.sort(key=lambda r: r.timestamp)
        first_ts = ts_records[0].timestamp
        last_ts = ts_records[-1].timestamp
        days_span = max((last_ts - first_ts).total_seconds() / 86400, 1)

        entries_per_day = len(ts_records) / days_span

        if entries_per_day < MIN_USN_ENTRIES_PER_DAY * 0.1:
            self.add_finding(Finding(
                title="USN Journal Appears Truncated",
                description=(
                    f"The USN Journal contains only {len(ts_records)} entries over "
                    f"{days_span:.1f} days ({entries_per_day:.0f} entries/day). "
                    f"An active Windows system typically generates {MIN_USN_ENTRIES_PER_DAY}+ "
                    f"entries per day. This low volume suggests the journal has been truncated "
                    f"or recreated, possibly via `fsutil usn deletejournal`."
                ),
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=[
                    f"Total records: {len(ts_records)}",
                    f"Time span: {first_ts} to {last_ts}",
                    f"Days covered: {days_span:.1f}",
                    f"Entries per day: {entries_per_day:.0f}",
                    f"Expected minimum: {MIN_USN_ENTRIES_PER_DAY} entries/day",
                ],
                timestamp=first_ts,
                recommendation=(
                    "Check for `fsutil` execution in Prefetch, Shimcache, or Amcache. "
                    "A truncated USN Journal means file system activity evidence has been destroyed. "
                    "Rely on MFT $FN timestamps and other artifacts for timeline analysis."
                ),
            ))

    def _check_usn_gaps(self, records: List[UsnRecord]):
        """Detect gaps in USN sequence numbers."""
        if len(records) < 2:
            return

        usn_values = sorted(set(r.usn for r in records if r.usn > 0))
        if len(usn_values) < 2:
            return

        # USN values increment by the record size (typically 64-500+ bytes)
        # Calculate typical increment
        increments = []
        for i in range(1, min(len(usn_values), 1000)):
            inc = usn_values[i] - usn_values[i - 1]
            if 0 < inc < 10000:
                increments.append(inc)

        if not increments:
            return

        median_increment = sorted(increments)[len(increments) // 2]
        large_gap_threshold = median_increment * 100  # 100x normal

        large_gaps = []
        usn_to_ts = {}
        for r in records:
            if r.usn > 0 and r.timestamp:
                usn_to_ts[r.usn] = r.timestamp

        for i in range(1, len(usn_values)):
            gap = usn_values[i] - usn_values[i - 1]
            if gap > large_gap_threshold:
                ts_before = usn_to_ts.get(usn_values[i - 1])
                ts_after = usn_to_ts.get(usn_values[i])
                estimated_missing = gap // max(median_increment, 1)
                large_gaps.append((usn_values[i - 1], usn_values[i], gap, estimated_missing, ts_before, ts_after))

        if not large_gaps:
            return

        total_estimated_missing = sum(g[3] for g in large_gaps)

        severity = Severity.HIGH if total_estimated_missing > 1000 else Severity.MEDIUM
        confidence = Confidence.HIGH

        evidence = [
            f"Large USN gaps found: {len(large_gaps)}",
            f"Median record increment: {median_increment} bytes",
            f"Gap threshold: {large_gap_threshold} bytes",
            f"Estimated total missing records: {total_estimated_missing}",
            "",
        ]

        for usn_before, usn_after, gap_size, est_missing, ts_before, ts_after in large_gaps[:10]:
            time_info = ""
            if ts_before and ts_after:
                time_info = f" ({ts_before} to {ts_after})"
            evidence.append(
                f"  USN {usn_before}→{usn_after}: gap={gap_size} bytes, "
                f"~{est_missing} missing records{time_info}"
            )

        self.add_finding(Finding(
            title="Gaps Detected in USN Journal Sequence",
            description=(
                f"Found {len(large_gaps)} large gap(s) in the USN Journal sequence numbers, "
                f"with an estimated {total_estimated_missing} missing records. These gaps indicate "
                f"that portions of the USN Journal have been removed or the journal was recreated."
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "Cross-reference gap time windows with event logs and MFT timestamps. "
                "The missing USN records may correspond to file operations the attacker wanted to hide."
            ),
        ))

    def _check_bulk_deletions(self, records: List[UsnRecord]):
        """Detect suspicious bulk file deletion patterns."""
        deletions = [r for r in records if r.is_file_delete and r.timestamp]
        if len(deletions) < BULK_DELETE_MIN_COUNT:
            return

        deletions.sort(key=lambda r: r.timestamp)

        # Sliding window to find bulk deletion bursts
        bursts = []
        window = timedelta(minutes=BULK_DELETE_WINDOW_MINUTES)
        i = 0

        while i < len(deletions):
            window_end = deletions[i].timestamp + window
            j = i
            while j < len(deletions) and deletions[j].timestamp <= window_end:
                j += 1

            count = j - i
            if count >= BULK_DELETE_MIN_COUNT:
                burst_records = deletions[i:j]
                # Check if deletions span multiple directories
                parents = set(r.parent_entry for r in burst_records)
                filenames = [r.filename for r in burst_records]
                bursts.append((
                    burst_records[0].timestamp,
                    burst_records[-1].timestamp,
                    count,
                    len(parents),
                    filenames,
                ))
                i = j
            else:
                i += 1

        if not bursts:
            return

        evidence = [f"Bulk deletion bursts found: {len(bursts)}", ""]

        for start_ts, end_ts, count, dir_count, filenames in bursts[:5]:
            duration = end_ts - start_ts
            evidence.append(
                f"  {start_ts} to {end_ts}: {count} files deleted "
                f"in {duration.total_seconds():.0f}s across {dir_count} directories"
            )
            # Show sample filenames
            for fn in filenames[:5]:
                evidence.append(f"    - {fn}")
            if len(filenames) > 5:
                evidence.append(f"    ... and {len(filenames) - 5} more")

        max_burst = max(bursts, key=lambda b: b[2])
        severity = Severity.HIGH if max_burst[2] > 100 else Severity.MEDIUM

        self.add_finding(Finding(
            title="Bulk File Deletion Detected",
            description=(
                f"Detected {len(bursts)} burst(s) of rapid file deletion. "
                f"The largest burst deleted {max_burst[2]} files within "
                f"{BULK_DELETE_WINDOW_MINUTES} minutes across {max_burst[3]} directories. "
                f"Rapid bulk deletion is a common anti-forensic technique to destroy evidence."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence=evidence,
            timestamp=bursts[0][0],
            recommendation=(
                "Investigate what triggered these deletions. Check for execution of wiping tools "
                "(SDelete, cipher.exe /w) or scripts around these timestamps. "
                "Attempt file carving in unallocated space to recover deleted content."
            ),
        ))

    def _check_orphaned_references(self, usn_records: List[UsnRecord], mft_parser: Optional[MftParser]):
        """
        Detect USN entries referencing MFT records that don't exist.
        This can indicate MFT record reuse after deletion or MFT tampering.
        """
        if not mft_parser or not mft_parser.entries:
            return

        mft_entries = set(e.entry_number for e in mft_parser.entries)
        orphaned = []

        for record in usn_records:
            if record.mft_entry > 0 and record.mft_entry not in mft_entries:
                orphaned.append(record)

        if not orphaned:
            return

        orphan_percentage = (len(orphaned) / len(usn_records)) * 100

        if orphan_percentage < 1.0:
            return  # Small percentage is normal (MFT record reuse)

        if orphan_percentage > MAX_ORPHAN_PERCENTAGE:
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        elif orphan_percentage > 5.0:
            severity = Severity.MEDIUM
            confidence = Confidence.MEDIUM
        else:
            severity = Severity.LOW
            confidence = Confidence.LOW

        evidence = [
            f"Orphaned USN entries: {len(orphaned)} ({orphan_percentage:.1f}%)",
            f"Total USN records: {len(usn_records)}",
            f"Total MFT entries: {len(mft_entries)}",
            "",
            "Sample orphaned entries:",
        ]
        for record in orphaned[:10]:
            evidence.append(
                f"  USN {record.usn}: MFT#{record.mft_entry} '{record.filename}' "
                f"({', '.join(record.reasons)}) at {record.timestamp}"
            )

        self.add_finding(Finding(
            title="Orphaned USN Journal References",
            description=(
                f"Found {len(orphaned)} USN Journal entries ({orphan_percentage:.1f}%) "
                f"referencing MFT record numbers that no longer exist in the MFT. "
                f"While some orphaning is normal due to MFT record reuse, a high percentage "
                f"may indicate MFT tampering or selective record deletion."
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=(
                "Compare orphaned entry timestamps with known incident window. "
                "High orphan rates during specific time periods suggest targeted deletion."
            ),
        ))

    def _check_journal_clearing_artifacts(self, records: List[UsnRecord]):
        """
        Detect artifacts of USN journal clearing tools.
        fsutil usn deletejournal creates a new journal with USN starting near 0.
        """
        if not records:
            return

        ts_records = sorted(
            [r for r in records if r.timestamp],
            key=lambda r: r.timestamp,
        )
        if not ts_records:
            return

        # Check if earliest records have very low USN values (journal was recreated)
        earliest = ts_records[:100]
        if any(r.usn < 1000 for r in earliest):
            # Low USN near start could be normal for a fresh system
            # Check if the system timestamp suggests it's not new
            first_ts = earliest[0].timestamp
            if first_ts and first_ts.year < datetime.now().year:
                return  # Could be from initial install

            # Check for sudden USN reset
            if len(ts_records) > 200:
                mid_records = ts_records[100:200]
                if all(r.usn > 10000 for r in mid_records):
                    self.add_finding(Finding(
                        title="USN Journal May Have Been Recreated",
                        description=(
                            "The USN Journal starts with very low sequence numbers, "
                            "which may indicate it was deleted and recreated using "
                            "`fsutil usn deletejournal` followed by `fsutil usn createjournal`."
                        ),
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence=[
                            f"Earliest USN value: {earliest[0].usn}",
                            f"Earliest timestamp: {earliest[0].timestamp}",
                            f"Records with USN < 1000: {sum(1 for r in earliest if r.usn < 1000)}",
                        ],
                        timestamp=earliest[0].timestamp,
                        recommendation=(
                            "Check Prefetch/Shimcache for fsutil.exe execution evidence. "
                            "A recreated journal means all prior file system activity evidence is lost."
                        ),
                    ))

    def _check_anti_forensic_deletions(self, records: List[UsnRecord]):
        """Detect deletions of known forensic artifact files."""
        forensic_targets = {
            ".evtx": "Event Log",
            ".pf": "Prefetch",
            "$mft": "MFT",
            "$logfile": "LogFile",
            "$usnjrnl": "USN Journal",
            "ntuser.dat": "User Registry Hive",
            "usrclass.dat": "User Class Registry Hive",
            "amcache.hve": "Amcache",
            "syscache.hve": "Syscache",
            "setupapi.dev.log": "Device Install Log",
        }

        deletions = [r for r in records if r.is_file_delete]
        forensic_deletions = []

        for record in deletions:
            fn_lower = record.filename.lower()
            for pattern, artifact_type in forensic_targets.items():
                if pattern in fn_lower:
                    forensic_deletions.append((record, artifact_type))
                    break

        if not forensic_deletions:
            return

        evidence = [f"Forensic artifact deletions found: {len(forensic_deletions)}", ""]
        for record, artifact_type in forensic_deletions:
            evidence.append(
                f"  {record.filename} ({artifact_type}) deleted at {record.timestamp}"
            )

        self.add_finding(Finding(
            title="Deletion of Forensic Artifact Files Detected",
            description=(
                f"The USN Journal records the deletion of {len(forensic_deletions)} "
                f"files that are known forensic artifacts (event logs, prefetch files, "
                f"registry hives, etc.). This is a strong indicator of deliberate "
                f"anti-forensic activity targeting investigation evidence."
            ),
            category=self.category,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            timestamp=forensic_deletions[0][0].timestamp,
            recommendation=(
                "This is confirmed anti-forensic activity. Determine who had access "
                "at the time of these deletions. Attempt recovery from Volume Shadow Copies, "
                "backup systems, or file carving. Correlate with authentication logs."
            ),
        ))
