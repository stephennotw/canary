"""
Sysmon/Audit Gap Detection Check.
Detects:
- Sysmon service stop/start events during incident window
- Sysmon configuration changes
- Gaps in Sysmon event sequence
- Audit policy changes that reduce logging coverage
- Windows Defender/security service tampering
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
from canary.parsers.evtx_parser import EvtxParser, EvtxRecord


# Sysmon Event IDs
SYSMON_CONFIG_CHANGE = 16       # Sysmon config state changed
SYSMON_SERVICE_STATE = 4         # Sysmon service state changed
SYSMON_ERROR = 255               # Sysmon error

# System Event IDs for service changes
SERVICE_INSTALL = 7045          # New service installed
SERVICE_START_STOP = 7036       # Service entered running/stopped state
SERVICE_CRASH = 7034            # Service terminated unexpectedly

# Security Event IDs for audit policy changes
AUDIT_POLICY_CHANGE = 4719     # System audit policy was changed
AUDIT_LOG_CLEARED = 1102       # Audit log was cleared
SPECIAL_LOGON = 4672           # Special privileges assigned

# Defender Event IDs (Microsoft-Windows-Windows Defender/Operational)
DEFENDER_DISABLED = 5001       # Real-time protection disabled
DEFENDER_CONFIG_CHANGE = 5007  # Configuration changed
DEFENDER_TAMPER = 5013         # Tamper protection blocked a change

# Security services to monitor
SECURITY_SERVICES = {
    "sysmon": "Sysmon (System Monitor)",
    "sysmon64": "Sysmon 64-bit",
    "windefend": "Windows Defender",
    "mpssvc": "Windows Firewall",
    "eventlog": "Windows Event Log Service",
    "sense": "Windows Defender ATP",
    "mssense": "Microsoft Defender for Endpoint",
    "wuauserv": "Windows Update",
    "bits": "Background Intelligent Transfer Service",
    "wscsvc": "Security Center",
}

# Minimum gap duration to flag
MIN_SYSMON_GAP = timedelta(minutes=5)


class SysmonGapCheck(BaseCheck):
    """Detects Sysmon/audit disruption and configuration tampering."""

    @property
    def name(self) -> str:
        return "Sysmon/Audit Gap Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.SYSMON

    @property
    def description(self) -> str:
        return (
            "Analyzes Sysmon and System event logs for evidence of security monitoring "
            "disruption: service stops, configuration changes, audit policy modifications, "
            "and gaps in monitoring coverage."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.evtx_paths or self.config.sysmon_log_path)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No event log data available")
            return []

        parser = EvtxParser()

        if self.config.mode == "live":
            self._load_live_logs(parser)
        else:
            paths = list(self.config.evtx_paths)
            if self.config.sysmon_log_path:
                paths.append(self.config.sysmon_log_path)
            for path in paths:
                try:
                    if os.path.isdir(path):
                        parser.parse_directory(path)
                    else:
                        parser.parse(path)
                except Exception as e:
                    self.add_error(f"Failed to parse {path}: {e}")

        if not parser.records:
            self.skip("No event records available for analysis")
            return []

        self.log(f"Analyzing {parser.record_count} records for Sysmon/audit gaps")

        # Run checks
        self._check_sysmon_config_changes(parser.records)
        self._check_sysmon_service_state(parser.records)
        self._check_sysmon_event_gaps(parser.records)
        self._check_audit_policy_changes(parser.records)
        self._check_security_service_stops(parser.records)
        self._check_defender_tampering(parser.records)

        return self._findings

    def _load_live_logs(self, parser: EvtxParser):
        """Load relevant logs from live system."""
        log_dir = r"C:\Windows\System32\winevt\Logs"
        target_logs = [
            "Microsoft-Windows-Sysmon%4Operational.evtx",
            "System.evtx",
            "Security.evtx",
            "Microsoft-Windows-Windows Defender%4Operational.evtx",
        ]
        for log_name in target_logs:
            log_path = os.path.join(log_dir, log_name)
            if os.path.exists(log_path):
                try:
                    parser.parse(log_path)
                except Exception as e:
                    self.add_error(f"Failed to parse {log_name}: {e}")

    def _check_sysmon_config_changes(self, records: List[EvtxRecord]):
        """Detect Sysmon configuration changes (Event ID 16)."""
        config_events = [
            r for r in records
            if r.event_id == SYSMON_CONFIG_CHANGE
        ]

        if not config_events:
            return

        evidence = [f"Sysmon configuration changes detected: {len(config_events)}", ""]

        for event in config_events:
            config_hash = event.data.get("ConfigurationFileHash", "Unknown")
            config_file = event.data.get("Configuration", "Unknown")
            evidence.append(
                f"  {event.timestamp}: Config changed"
                f" (file: {config_file}, hash: {config_hash})"
            )

        # Check if changes happened during incident window
        in_incident_window = False
        if self.config.incident_start and self.config.incident_end:
            in_incident_window = any(
                e.timestamp and self.config.incident_start <= e.timestamp <= self.config.incident_end
                for e in config_events
            )

        severity = Severity.HIGH if in_incident_window else Severity.MEDIUM
        confidence = Confidence.HIGH if in_incident_window else Confidence.MEDIUM

        self.add_finding(Finding(
            title="Sysmon Configuration Changed",
            description=(
                f"Detected {len(config_events)} Sysmon configuration change event(s). "
                f"An attacker may modify Sysmon config to exclude their activities from logging. "
                + ("These changes occurred DURING the incident window." if in_incident_window else "")
            ),
            category=self.category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            timestamp=config_events[0].timestamp,
            recommendation=(
                "Compare the configuration hash before and after each change. "
                "Determine if the new config excludes any processes, paths, or event types "
                "that would have captured attacker activity."
            ),
        ))

    def _check_sysmon_service_state(self, records: List[EvtxRecord]):
        """Detect Sysmon service state changes (started/stopped)."""
        # Look in System log for service state changes mentioning Sysmon
        service_events = [
            r for r in records
            if r.event_id in (SERVICE_START_STOP, SERVICE_CRASH, SERVICE_INSTALL)
        ]

        sysmon_events = []
        for event in service_events:
            service_name = (
                event.data.get("param1", "") +
                event.data.get("ServiceName", "") +
                event.data.get("ImagePath", "")
            ).lower()
            if "sysmon" in service_name:
                state = event.data.get("param2", event.data.get("State", "Unknown"))
                sysmon_events.append((event, state))

        if not sysmon_events:
            return

        # Check for stop events
        stops = [(e, s) for e, s in sysmon_events if "stop" in str(s).lower()]

        if stops:
            evidence = [f"Sysmon service state changes: {len(sysmon_events)}", ""]
            for event, state in sysmon_events:
                evidence.append(f"  {event.timestamp}: State = {state}")

            self.add_finding(Finding(
                title="Sysmon Service Was Stopped",
                description=(
                    f"The Sysmon service was stopped {len(stops)} time(s). "
                    f"Stopping Sysmon disables all process, network, and file monitoring. "
                    f"This is a critical anti-forensic action that creates a monitoring blind spot."
                ),
                category=self.category,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                timestamp=stops[0][0].timestamp,
                recommendation=(
                    "Determine who stopped Sysmon and why. Correlate the stop/start times "
                    "with other event sources to identify what happened during the monitoring gap. "
                    "Check for service uninstall events."
                ),
            ))

    def _check_sysmon_event_gaps(self, records: List[EvtxRecord]):
        """Detect time gaps in Sysmon event generation."""
        sysmon_records = [
            r for r in records
            if r.timestamp and (
                "sysmon" in (r.provider or "").lower() or
                "sysmon" in (r.channel or "").lower()
            )
        ]

        if len(sysmon_records) < 10:
            return

        sysmon_records.sort(key=lambda r: r.timestamp)

        gaps = []
        for i in range(1, len(sysmon_records)):
            gap = sysmon_records[i].timestamp - sysmon_records[i - 1].timestamp
            if gap > MIN_SYSMON_GAP:
                gaps.append((
                    sysmon_records[i - 1].timestamp,
                    sysmon_records[i].timestamp,
                    gap,
                    sysmon_records[i - 1].record_id,
                    sysmon_records[i].record_id,
                ))

        if not gaps:
            return

        # Filter out quiet hours (optional)
        suspicious_gaps = [g for g in gaps if not (2 <= g[0].hour <= 5)]

        if not suspicious_gaps:
            return

        max_gap = max(suspicious_gaps, key=lambda g: g[2])
        severity = Severity.HIGH if max_gap[2] > timedelta(hours=1) else Severity.MEDIUM

        evidence = [
            f"Sysmon event gaps detected: {len(suspicious_gaps)}",
            f"Total Sysmon events: {len(sysmon_records)}",
            "",
        ]
        for start, end, duration, rec_start, rec_end in suspicious_gaps[:10]:
            evidence.append(
                f"  {start} to {end} ({duration}) "
                f"[records {rec_start}→{rec_end}]"
            )

        self.add_finding(Finding(
            title="Gaps in Sysmon Event Coverage",
            description=(
                f"Found {len(suspicious_gaps)} gap(s) in Sysmon event generation. "
                f"The longest gap is {max_gap[2]}. During these gaps, Sysmon was either "
                f"stopped, reconfigured to exclude events, or events were deleted."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence=evidence,
            timestamp=max_gap[0],
            recommendation=(
                "Cross-reference gap windows with System log service events and "
                "Sysmon config change events (Event ID 16). Check if any security "
                "services were stopped during these windows."
            ),
        ))

    def _check_audit_policy_changes(self, records: List[EvtxRecord]):
        """Detect audit policy changes that may reduce logging coverage."""
        policy_events = [
            r for r in records
            if r.event_id == AUDIT_POLICY_CHANGE and r.timestamp
        ]

        if not policy_events:
            return

        evidence = [f"Audit policy change events: {len(policy_events)}", ""]

        for event in policy_events[:10]:
            subject = event.data.get("SubjectUserName", "Unknown")
            category = event.data.get("CategoryId", event.data.get("Category", "Unknown"))
            subcategory = event.data.get("SubcategoryGuid", event.data.get("Subcategory", "Unknown"))
            evidence.append(
                f"  {event.timestamp}: Changed by {subject} "
                f"(Category: {category}, Subcategory: {subcategory})"
            )

        in_incident = False
        if self.config.incident_start and self.config.incident_end:
            in_incident = any(
                self.config.incident_start <= e.timestamp <= self.config.incident_end
                for e in policy_events if e.timestamp
            )

        severity = Severity.HIGH if in_incident else Severity.MEDIUM

        self.add_finding(Finding(
            title="Audit Policy Changes Detected",
            description=(
                f"Detected {len(policy_events)} audit policy change event(s) (Event ID 4719). "
                f"An attacker may modify audit policies to disable logging of specific actions "
                f"like logon events, object access, or privilege use."
                + (" Changes detected DURING incident window." if in_incident else "")
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence=evidence,
            timestamp=policy_events[0].timestamp,
            recommendation=(
                "Review each policy change to determine if it reduced security logging. "
                "Compare current audit policy with organizational baseline. "
                "Correlate with who made the change and their authorization."
            ),
        ))

    def _check_security_service_stops(self, records: List[EvtxRecord]):
        """Detect stops of security-related services."""
        service_events = [
            r for r in records
            if r.event_id in (SERVICE_START_STOP, SERVICE_CRASH) and r.timestamp
        ]

        stopped_services = []
        for event in service_events:
            service_name = (
                event.data.get("param1", "") +
                event.data.get("ServiceName", "")
            ).lower()
            state = str(event.data.get("param2", event.data.get("State", ""))).lower()

            if "stop" in state or "terminated" in state:
                for svc_key, svc_desc in SECURITY_SERVICES.items():
                    if svc_key in service_name:
                        stopped_services.append((event, svc_desc))
                        break

        if not stopped_services:
            return

        evidence = [f"Security service stops detected: {len(stopped_services)}", ""]
        for event, desc in stopped_services:
            evidence.append(f"  {event.timestamp}: {desc} stopped")

        severity = Severity.HIGH
        if any("sysmon" in desc.lower() or "defender" in desc.lower() for _, desc in stopped_services):
            severity = Severity.CRITICAL

        self.add_finding(Finding(
            title="Security Service(s) Stopped",
            description=(
                f"Detected {len(stopped_services)} security service stop event(s). "
                f"Stopping security services creates monitoring blind spots that attackers "
                f"exploit to perform malicious actions undetected."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence=evidence,
            timestamp=stopped_services[0][0].timestamp,
            recommendation=(
                "Determine who stopped each service and whether it was authorized. "
                "Check for corresponding start events. Identify what activity occurred "
                "while the services were down."
            ),
        ))

    def _check_defender_tampering(self, records: List[EvtxRecord]):
        """Detect Windows Defender tampering events."""
        defender_events = [
            r for r in records
            if r.event_id in (DEFENDER_DISABLED, DEFENDER_CONFIG_CHANGE, DEFENDER_TAMPER)
            and r.timestamp
        ]

        if not defender_events:
            return

        disabled_events = [e for e in defender_events if e.event_id == DEFENDER_DISABLED]
        config_events = [e for e in defender_events if e.event_id == DEFENDER_CONFIG_CHANGE]
        tamper_events = [e for e in defender_events if e.event_id == DEFENDER_TAMPER]

        evidence = []
        if disabled_events:
            evidence.append(f"Defender real-time protection disabled: {len(disabled_events)} time(s)")
        if config_events:
            evidence.append(f"Defender configuration changes: {len(config_events)}")
        if tamper_events:
            evidence.append(f"Tamper protection triggered: {len(tamper_events)}")

        evidence.append("")
        for event in defender_events[:10]:
            event_desc = {
                DEFENDER_DISABLED: "Real-time protection DISABLED",
                DEFENDER_CONFIG_CHANGE: "Configuration changed",
                DEFENDER_TAMPER: "Tamper protection blocked change",
            }.get(event.event_id, f"Event {event.event_id}")
            evidence.append(f"  {event.timestamp}: {event_desc}")

        severity = Severity.CRITICAL if disabled_events else Severity.HIGH

        self.add_finding(Finding(
            title="Windows Defender Tampering Detected",
            description=(
                f"Detected {len(defender_events)} Windows Defender-related security events. "
                + (f"Real-time protection was DISABLED {len(disabled_events)} time(s). " if disabled_events else "")
                + (f"Tamper protection blocked {len(tamper_events)} unauthorized change(s). " if tamper_events else "")
                + "This indicates an attempt to weaken endpoint security."
            ),
            category=self.category,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            timestamp=defender_events[0].timestamp,
            recommendation=(
                "Investigate who disabled Defender and correlate with subsequent activity. "
                "Check if malware was executed during the period Defender was disabled."
            ),
        ))
