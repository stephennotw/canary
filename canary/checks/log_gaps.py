"""
Log Gap Detection Check.
Detects:
- Missing sequential Event Log record IDs (deleted records)
- Event ID 1102 (Security log cleared) without corresponding admin activity
- Suspicious time gaps in log sequences
- Channels with abnormally low record counts
"""

import os
from collections import defaultdict
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
from canary.parsers.evtx_parser import EvtxParser, EvtxRecord


# Event IDs indicating log clearing
LOG_CLEAR_EVENT_IDS = {
    1102,  # Security log was cleared
    104,   # System log was cleared (System channel)
}

# Minimum gap size (in record IDs) to consider suspicious
MIN_GAP_SIZE = 2

# Minimum time gap (in minutes) to flag
MIN_TIME_GAP_MINUTES = 30

# Expected minimum records per hour for active channels
MIN_RECORDS_PER_HOUR = {
    "Security": 5,
    "System": 2,
    "Microsoft-Windows-Sysmon/Operational": 10,
}


class LogGapCheck(BaseCheck):
    """Detects evidence of log manipulation and clearing."""

    @property
    def name(self) -> str:
        return "Log Gap Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.LOG_GAPS

    @property
    def description(self) -> str:
        return (
            "Analyzes Windows Event Logs for missing record IDs, log clearing events, "
            "suspicious time gaps, and abnormally sparse logging periods."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.evtx_paths)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No EVTX files or paths configured")
            return []

        parser = EvtxParser()

        # Load data
        if self.config.mode == "live":
            self._load_live_logs(parser)
        else:
            for path in self.config.evtx_paths:
                try:
                    if os.path.isdir(path):
                        parser.parse_directory(path)
                    else:
                        parser.parse(path)
                    self.log(f"Parsed {path}: {parser.record_count} records")
                except Exception as e:
                    self.add_error(f"Failed to parse {path}: {e}")

        if not parser.records:
            self.skip("No log records found to analyze")
            return []

        self.log(f"Analyzing {parser.record_count} total records")

        # Group records by channel
        channels = self._group_by_channel(parser.records)

        # Run detection checks
        self._check_record_id_gaps(channels)
        self._check_log_clear_events(parser.records)
        self._check_time_gaps(channels)
        self._check_sparse_channels(channels)
        self._check_log_clear_without_context(parser.records)

        return self._findings

    def _load_live_logs(self, parser: EvtxParser):
        """Load logs from live system."""
        log_dir = r"C:\Windows\System32\winevt\Logs"
        if os.path.isdir(log_dir):
            important_logs = [
                "Security.evtx",
                "System.evtx",
                "Application.evtx",
                "Microsoft-Windows-Sysmon%4Operational.evtx",
                "Microsoft-Windows-PowerShell%4Operational.evtx",
                "Microsoft-Windows-TaskScheduler%4Operational.evtx",
            ]
            for log_name in important_logs:
                log_path = os.path.join(log_dir, log_name)
                if os.path.exists(log_path):
                    try:
                        parser.parse(log_path)
                    except Exception as e:
                        self.add_error(f"Failed to parse {log_name}: {e}")

    def _group_by_channel(self, records: List[EvtxRecord]) -> Dict[str, List[EvtxRecord]]:
        """Group records by their log channel."""
        channels: Dict[str, List[EvtxRecord]] = defaultdict(list)
        for record in records:
            channel = record.channel or "Unknown"
            channels[channel].append(record)
        # Sort each channel by record ID
        for channel in channels:
            channels[channel].sort(key=lambda r: r.record_id)
        return channels

    def _check_record_id_gaps(self, channels: Dict[str, List[EvtxRecord]]):
        """Detect missing sequential record IDs within each channel."""
        for channel, records in channels.items():
            if len(records) < 2:
                continue

            record_ids = sorted(set(r.record_id for r in records if r.record_id > 0))
            if len(record_ids) < 2:
                continue

            gaps: List[Tuple[int, int, int]] = []  # (start, end, gap_size)
            for i in range(1, len(record_ids)):
                gap = record_ids[i] - record_ids[i - 1]
                if gap > MIN_GAP_SIZE:
                    gaps.append((record_ids[i - 1], record_ids[i], gap - 1))

            if not gaps:
                continue

            total_missing = sum(g[2] for g in gaps)

            # Determine severity based on gap characteristics
            max_gap = max(g[2] for g in gaps)
            if max_gap > 1000:
                severity = Severity.CRITICAL
                confidence = Confidence.CONFIRMED
            elif max_gap > 100:
                severity = Severity.HIGH
                confidence = Confidence.HIGH
            elif max_gap > 10:
                severity = Severity.MEDIUM
                confidence = Confidence.HIGH
            else:
                severity = Severity.LOW
                confidence = Confidence.MEDIUM

            # Find approximate timestamps for gaps
            id_to_ts = {r.record_id: r.timestamp for r in records if r.timestamp}
            gap_details = []
            for start_id, end_id, count in gaps[:10]:  # Report top 10 gaps
                ts_before = id_to_ts.get(start_id)
                ts_after = id_to_ts.get(end_id)
                time_span = ""
                if ts_before and ts_after:
                    time_span = f" ({ts_before.strftime('%Y-%m-%d %H:%M:%S')} to {ts_after.strftime('%Y-%m-%d %H:%M:%S')})"
                gap_details.append(
                    f"Records {start_id}→{end_id}: {count} missing{time_span}"
                )

            evidence = [
                f"Channel: {channel}",
                f"Total records analyzed: {len(record_ids)}",
                f"Total gaps found: {len(gaps)}",
                f"Total missing records: {total_missing}",
            ] + gap_details

            # Determine timestamp for finding (use the largest gap)
            largest_gap = max(gaps, key=lambda g: g[2])
            ts = id_to_ts.get(largest_gap[0])

            self.add_finding(Finding(
                title=f"Missing Event Log Records in {channel}",
                description=(
                    f"Detected {len(gaps)} gap(s) in sequential record IDs in the {channel} log, "
                    f"with {total_missing} total missing records. The largest gap spans "
                    f"{largest_gap[2]} records (IDs {largest_gap[0]}→{largest_gap[1]}). "
                    f"This strongly indicates deliberate log record deletion."
                ),
                category=self.category,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                timestamp=ts,
                recommendation=(
                    "Investigate the time windows of the gaps. Cross-reference with other "
                    "artifact sources (Sysmon, USN Journal) to determine what activity occurred "
                    "during the missing periods. Check for Event ID 1102/104 around these timestamps."
                ),
            ))

    def _check_log_clear_events(self, records: List[EvtxRecord]):
        """Detect Event ID 1102 (log cleared) and Event ID 104 events."""
        clear_events = [r for r in records if r.event_id in LOG_CLEAR_EVENT_IDS]

        for event in clear_events:
            user = event.data.get("SubjectUserName", event.user_sid or "Unknown")
            channel_cleared = "Security" if event.event_id == 1102 else event.data.get("Channel", "Unknown")

            self.add_finding(Finding(
                title=f"Event Log Cleared: {channel_cleared}",
                description=(
                    f"Event ID {event.event_id} detected — the {channel_cleared} log was explicitly cleared "
                    f"by user '{user}' at {event.timestamp}. This is a direct indicator of anti-forensic activity "
                    f"unless performed during documented maintenance."
                ),
                category=self.category,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence=[
                    f"Event ID: {event.event_id}",
                    f"Record ID: {event.record_id}",
                    f"Timestamp: {event.timestamp}",
                    f"User: {user}",
                    f"Channel cleared: {channel_cleared}",
                    f"Provider: {event.provider}",
                ],
                timestamp=event.timestamp,
                recommendation=(
                    "Determine if this log clearing was authorized (planned maintenance, audit). "
                    "If not, this is high-priority anti-forensic activity. Check other log channels "
                    "and artifact sources for activity before and after this timestamp."
                ),
            ))

    def _check_time_gaps(self, channels: Dict[str, List[EvtxRecord]]):
        """Detect suspicious time gaps within log channels."""
        for channel, records in channels.items():
            ts_records = [(r.timestamp, r) for r in records if r.timestamp]
            if len(ts_records) < 2:
                continue

            ts_records.sort(key=lambda x: x[0])
            min_gap = timedelta(minutes=MIN_TIME_GAP_MINUTES)

            # Adjust min gap for low-volume channels
            if channel in MIN_RECORDS_PER_HOUR:
                expected_rate = MIN_RECORDS_PER_HOUR[channel]
                min_gap = timedelta(minutes=max(10, 60 // max(expected_rate, 1) * 5))

            time_gaps = []
            for i in range(1, len(ts_records)):
                gap = ts_records[i][0] - ts_records[i - 1][0]
                if gap > min_gap:
                    # Check if this is during expected quiet hours (2am-5am)
                    hour = ts_records[i - 1][0].hour
                    is_quiet_hours = 2 <= hour <= 5
                    time_gaps.append((
                        ts_records[i - 1][0],
                        ts_records[i][0],
                        gap,
                        ts_records[i - 1][1].record_id,
                        ts_records[i][1].record_id,
                        is_quiet_hours,
                    ))

            # Filter out quiet-hours gaps for severity calculation
            suspicious_gaps = [g for g in time_gaps if not g[5]]

            if not suspicious_gaps:
                continue

            max_gap_duration = max(g[2] for g in suspicious_gaps)
            if max_gap_duration > timedelta(hours=12):
                severity = Severity.HIGH
                confidence = Confidence.HIGH
            elif max_gap_duration > timedelta(hours=2):
                severity = Severity.MEDIUM
                confidence = Confidence.MEDIUM
            else:
                severity = Severity.LOW
                confidence = Confidence.LOW

            evidence = [f"Channel: {channel}", f"Non-quiet-hour gaps found: {len(suspicious_gaps)}"]
            for start_ts, end_ts, duration, rec_start, rec_end, _ in suspicious_gaps[:5]:
                evidence.append(
                    f"Gap: {start_ts.strftime('%Y-%m-%d %H:%M:%S')} to "
                    f"{end_ts.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"(duration: {duration}, records {rec_start}→{rec_end})"
                )

            self.add_finding(Finding(
                title=f"Suspicious Time Gaps in {channel} Log",
                description=(
                    f"Detected {len(suspicious_gaps)} suspicious time gap(s) in the {channel} log "
                    f"outside of normal quiet hours. The longest gap is {max_gap_duration}. "
                    f"Time gaps during active hours may indicate log suppression or service disruption."
                ),
                category=self.category,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                timestamp=suspicious_gaps[0][0],
                recommendation=(
                    "Cross-reference time gaps with system uptime data (Event ID 6005/6006) and "
                    "Sysmon service status. If the system was running during these gaps, "
                    "log suppression is likely."
                ),
            ))

    def _check_sparse_channels(self, channels: Dict[str, List[EvtxRecord]]):
        """Check if normally verbose channels have abnormally few records."""
        for channel, expected_rate in MIN_RECORDS_PER_HOUR.items():
            records = channels.get(channel, [])
            if not records:
                continue

            ts_records = [r for r in records if r.timestamp]
            if len(ts_records) < 2:
                continue

            ts_records.sort(key=lambda r: r.timestamp)
            first_ts = ts_records[0].timestamp
            last_ts = ts_records[-1].timestamp
            hours_span = max((last_ts - first_ts).total_seconds() / 3600, 1)

            actual_rate = len(ts_records) / hours_span
            if actual_rate < expected_rate * 0.1:  # Less than 10% of expected
                self.add_finding(Finding(
                    title=f"Abnormally Sparse Logging in {channel}",
                    description=(
                        f"The {channel} log contains only {len(ts_records)} records over "
                        f"{hours_span:.1f} hours ({actual_rate:.1f} records/hour). "
                        f"Expected minimum rate is ~{expected_rate} records/hour. "
                        f"This may indicate partial log deletion or logging disruption."
                    ),
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=[
                        f"Channel: {channel}",
                        f"Records: {len(ts_records)}",
                        f"Time span: {first_ts} to {last_ts}",
                        f"Actual rate: {actual_rate:.2f} records/hour",
                        f"Expected minimum: {expected_rate} records/hour",
                    ],
                    timestamp=first_ts,
                    recommendation=(
                        "Verify that the logging service was running during this period. "
                        "Check if audit policies were changed or Sysmon was disabled."
                    ),
                ))

    def _check_log_clear_without_context(self, records: List[EvtxRecord]):
        """Detect log clearing events that lack surrounding admin activity."""
        clear_events = [r for r in records if r.event_id in LOG_CLEAR_EVENT_IDS]
        if not clear_events:
            return

        # Look for admin logon events (4624 type 10 or type 2/7) near clear events
        logon_events = [r for r in records if r.event_id == 4624]

        for clear_event in clear_events:
            if not clear_event.timestamp:
                continue

            window_start = clear_event.timestamp - timedelta(minutes=15)
            window_end = clear_event.timestamp + timedelta(minutes=5)

            nearby_logons = [
                r for r in logon_events
                if r.timestamp and window_start <= r.timestamp <= window_end
            ]

            if not nearby_logons:
                self.add_finding(Finding(
                    title="Log Cleared Without Nearby Admin Logon",
                    description=(
                        f"Event log was cleared at {clear_event.timestamp} but no administrative "
                        f"logon events (Event ID 4624) were found within 15 minutes before or "
                        f"5 minutes after the clearing. This suggests the clearing may have been "
                        f"performed via a pre-existing session or automated script."
                    ),
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=[
                        f"Clear event timestamp: {clear_event.timestamp}",
                        f"Clear event ID: {clear_event.event_id}",
                        f"Search window: {window_start} to {window_end}",
                        f"Nearby logon events found: 0",
                    ],
                    timestamp=clear_event.timestamp,
                    recommendation=(
                        "Investigate what session was active at this time. Check for RDP sessions, "
                        "scheduled tasks, or service accounts that could have cleared the log."
                    ),
                ))
