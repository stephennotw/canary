"""
Registry Anomaly Detection Check.
Detects:
- Wiped or missing expected registry keys
- LastWrite timestamp anomalies on critical keys
- Disabled security features via registry
- Anti-forensic tool registry artifacts
- Persistence mechanisms that were partially cleaned up
"""

import os
import csv
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

# Critical registry keys that should always exist
EXPECTED_KEYS = {
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters": {
        "description": "Prefetch configuration",
        "expected_values": {"EnablePrefetcher": ["1", "2", "3"]},
        "tamper_indicator": "Prefetch disabled (value=0) hides execution evidence",
    },
    r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog": {
        "description": "Event Log service configuration",
        "tamper_indicator": "Missing or modified Event Log config disrupts logging",
    },
    r"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon": {
        "description": "Sysmon service registration",
        "tamper_indicator": "Missing Sysmon service key = service was uninstalled",
    },
    r"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64": {
        "description": "Sysmon64 service registration",
        "tamper_indicator": "Missing Sysmon64 service key = service was uninstalled",
    },
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": {
        "description": "Startup programs (persistence location)",
        "tamper_indicator": "Modified Run key may indicate persistence or cleanup",
    },
}

# Registry values that indicate security features were disabled
SECURITY_DISABLING_INDICATORS = {
    r"EnablePrefetcher": {
        "disabled_value": "0",
        "description": "Prefetch disabled - hides program execution evidence",
        "severity": Severity.HIGH,
    },
    r"EnableSuperfetch": {
        "disabled_value": "0",
        "description": "Superfetch disabled - reduces execution tracking",
        "severity": Severity.MEDIUM,
    },
    r"DisableAntiSpyware": {
        "disabled_value": "1",
        "description": "Windows Defender Anti-Spyware disabled via registry",
        "severity": Severity.CRITICAL,
    },
    r"DisableAntiVirus": {
        "disabled_value": "1",
        "description": "Windows Defender Anti-Virus disabled via registry",
        "severity": Severity.CRITICAL,
    },
    r"DisableRealtimeMonitoring": {
        "disabled_value": "1",
        "description": "Windows Defender real-time monitoring disabled",
        "severity": Severity.CRITICAL,
    },
    r"DisableBehaviorMonitoring": {
        "disabled_value": "1",
        "description": "Defender behavior monitoring disabled",
        "severity": Severity.HIGH,
    },
    r"DisableOnAccessProtection": {
        "disabled_value": "1",
        "description": "Defender on-access protection disabled",
        "severity": Severity.HIGH,
    },
    r"DisableScanOnRealtimeEnable": {
        "disabled_value": "1",
        "description": "Defender scan on real-time enable disabled",
        "severity": Severity.HIGH,
    },
    r"DisableIOAVProtection": {
        "disabled_value": "1",
        "description": "Defender IOAV protection disabled",
        "severity": Severity.HIGH,
    },
    r"SubmitSamplesConsent": {
        "disabled_value": "0",
        "description": "Defender sample submission disabled",
        "severity": Severity.MEDIUM,
    },
    r"SpynetReporting": {
        "disabled_value": "0",
        "description": "Defender cloud-based protection disabled",
        "severity": Severity.MEDIUM,
    },
    r"Start": {
        # In Services context - Start=4 means disabled
        "disabled_value": "4",
        "description": "Service start type set to Disabled",
        "severity": Severity.MEDIUM,
        "context_key": "Services",
    },
    r"ConsentPromptBehaviorAdmin": {
        "disabled_value": "0",
        "description": "UAC consent prompt disabled for admins (silent elevation)",
        "severity": Severity.HIGH,
    },
    r"EnableLUA": {
        "disabled_value": "0",
        "description": "UAC completely disabled",
        "severity": Severity.HIGH,
    },
}

# Known persistence registry locations
PERSISTENCE_LOCATIONS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
]


class RegistryEntry:
    """Represents a parsed registry entry."""

    def __init__(self):
        self.key_path: str = ""
        self.value_name: str = ""
        self.value_data: str = ""
        self.value_type: str = ""
        self.last_write: Optional[datetime] = None
        self.hive: str = ""


class RegistryCheck(BaseCheck):
    """Detects registry anomalies indicative of anti-forensic activity."""

    @property
    def name(self) -> str:
        return "Registry Anomaly Detector"

    @property
    def category(self) -> CheckCategory:
        return CheckCategory.REGISTRY

    @property
    def description(self) -> str:
        return (
            "Analyzes registry data for disabled security features, missing expected keys, "
            "anti-forensic tool artifacts, timestamp anomalies, and partially cleaned persistence."
        )

    def can_run(self) -> bool:
        if self.config.mode == "live":
            return True
        return bool(self.config.registry_hive_paths)

    def run(self) -> List[Finding]:
        if not self.can_run():
            self.skip("No registry data source configured")
            return []

        entries = []
        if self.config.mode == "live":
            entries = self._load_live_registry()
        else:
            for path in self.config.registry_hive_paths:
                try:
                    parsed = self._parse_registry_export(path)
                    entries.extend(parsed)
                    self.log(f"Parsed registry export: {len(parsed)} entries from {path}")
                except Exception as e:
                    self.add_error(f"Failed to parse registry export {path}: {e}")

        if not entries:
            # Even without entries, we can do live checks
            if self.config.mode == "live":
                self._check_live_security_settings()
                return self._findings
            self.skip("No registry entries loaded")
            return []

        self.log(f"Analyzing {len(entries)} registry entries")

        # Run checks
        self._check_security_disabled(entries)
        self._check_timestamp_anomalies(entries)
        self._check_antiforensic_artifacts(entries)
        self._check_persistence_remnants(entries)
        self._check_usn_journal_config(entries)

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
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str[:26].rstrip("Z"), fmt)
            except ValueError:
                continue
        return None

    def _load_live_registry(self) -> List[RegistryEntry]:
        """Load critical registry values from live system."""
        entries = []
        try:
            import winreg
        except ImportError:
            self.add_error("winreg not available (not Windows)")
            return entries

        # Check security-relevant keys
        checks = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
             "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows Defender",
             "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
             "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
             "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "HKLM"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             "HKCU"),
        ]

        for hive, key_path, hive_name in checks:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, data, reg_type = winreg.EnumValue(key, i)
                            entry = RegistryEntry()
                            entry.key_path = f"{hive_name}\\{key_path}"
                            entry.value_name = name
                            entry.value_data = str(data)
                            entry.value_type = str(reg_type)
                            entry.hive = hive_name
                            entries.append(entry)
                            i += 1
                        except OSError:
                            break
            except (OSError, FileNotFoundError):
                continue

        return entries

    def _parse_registry_export(self, path: str) -> List[RegistryEntry]:
        """Parse a registry export file (CSV from RECmd, RegRipper, etc.)."""
        entries = []
        ext = os.path.splitext(path)[1].lower()

        if ext == ".csv":
            entries = self._parse_csv_export(path)
        else:
            # Try CSV format
            try:
                entries = self._parse_csv_export(path)
            except Exception:
                pass

        return entries

    def _parse_csv_export(self, path: str) -> List[RegistryEntry]:
        """Parse RECmd or generic CSV registry export."""
        entries = []
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = RegistryEntry()

                    entry.key_path = row.get("HivePath", row.get("KeyPath",
                                    row.get("Key", row.get("key_path", ""))))
                    entry.value_name = row.get("ValueName", row.get("Name",
                                      row.get("value_name", "")))
                    entry.value_data = row.get("ValueData", row.get("Data",
                                      row.get("Value", row.get("value_data", ""))))
                    entry.value_type = row.get("ValueType", row.get("Type",
                                      row.get("value_type", "")))

                    ts_str = row.get("LastWriteTimestamp", row.get("LastWrite",
                             row.get("Timestamp", row.get("last_write", ""))))
                    entry.last_write = self._parse_timestamp(ts_str)

                    entries.append(entry)
                except (ValueError, KeyError):
                    continue
        return entries

    def _check_live_security_settings(self):
        """Check security settings on live Windows system."""
        try:
            import winreg
        except ImportError:
            return

        disabled_features = []

        # Check Prefetch
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                 r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters") as key:
                val, _ = winreg.QueryValueEx(key, "EnablePrefetcher")
                if val == 0:
                    disabled_features.append(("Prefetch", "EnablePrefetcher=0", Severity.HIGH))
        except (OSError, FileNotFoundError):
            disabled_features.append(("Prefetch", "Registry key not found", Severity.MEDIUM))

        # Check Defender policies
        defender_checks = [
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1", Severity.CRITICAL),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
             "DisableRealtimeMonitoring", "1", Severity.CRITICAL),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
             "DisableBehaviorMonitoring", "1", Severity.HIGH),
        ]

        for key_path, value_name, bad_value, severity in defender_checks:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    val, _ = winreg.QueryValueEx(key, value_name)
                    if str(val) == bad_value:
                        disabled_features.append((
                            f"Defender: {value_name}",
                            f"{value_name}={val}",
                            severity,
                        ))
            except (OSError, FileNotFoundError):
                pass

        # Check UAC
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
                val, _ = winreg.QueryValueEx(key, "EnableLUA")
                if val == 0:
                    disabled_features.append(("UAC", "EnableLUA=0 (UAC disabled)", Severity.HIGH))
        except (OSError, FileNotFoundError):
            pass

        if disabled_features:
            max_severity = max(f[2] for f in disabled_features)
            evidence = [f"Security features disabled: {len(disabled_features)}", ""]
            for name, detail, sev in disabled_features:
                evidence.append(f"  [{sev.value.upper()}] {name}: {detail}")

            self.add_finding(Finding(
                title="Security Features Disabled via Registry",
                description=(
                    f"Found {len(disabled_features)} security feature(s) disabled via registry "
                    f"settings on this live system. Disabling security features is a common "
                    f"anti-forensic and defense evasion technique."
                ),
                category=self.category,
                severity=max_severity,
                confidence=Confidence.CONFIRMED,
                evidence=evidence,
                recommendation=(
                    "Determine when and how these settings were changed. "
                    "Check Group Policy and local policy for the source of these settings. "
                    "Re-enable disabled security features immediately."
                ),
            ))

    def _check_security_disabled(self, entries: List[RegistryEntry]):
        """Check for registry values indicating disabled security features."""
        disabled = []

        for entry in entries:
            value_name = entry.value_name
            if value_name in SECURITY_DISABLING_INDICATORS:
                indicator = SECURITY_DISABLING_INDICATORS[value_name]
                if str(entry.value_data).strip() == indicator["disabled_value"]:
                    # Check context if needed
                    context_key = indicator.get("context_key")
                    if context_key and context_key not in entry.key_path:
                        continue
                    disabled.append((entry, indicator))

        if not disabled:
            return

        max_severity = max(ind["severity"] for _, ind in disabled)
        evidence = [f"Disabled security features found: {len(disabled)}", ""]

        for entry, indicator in disabled:
            evidence.append(
                f"  [{indicator['severity'].value.upper()}] {indicator['description']}"
            )
            evidence.append(
                f"    Key: {entry.key_path}\\{entry.value_name} = {entry.value_data}"
            )
            if entry.last_write:
                evidence.append(f"    Last modified: {entry.last_write}")

        self.add_finding(Finding(
            title="Security Features Disabled via Registry",
            description=(
                f"Found {len(disabled)} registry value(s) that disable security features. "
                f"This includes antivirus, monitoring, UAC, or forensic artifact collection. "
                f"These modifications are strong indicators of defense evasion."
            ),
            category=self.category,
            severity=max_severity,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            timestamp=disabled[0][0].last_write,
            recommendation=(
                "Determine when and who modified these values. Cross-reference with "
                "authentication logs. Re-enable all disabled security features."
            ),
        ))

    def _check_timestamp_anomalies(self, entries: List[RegistryEntry]):
        """Check for registry key timestamp anomalies."""
        ts_entries = [e for e in entries if e.last_write]
        if len(ts_entries) < 10:
            return

        now = datetime.now()
        future_entries = [e for e in ts_entries if e.last_write > now + timedelta(days=1)]

        if future_entries:
            evidence = [f"Registry keys with future timestamps: {len(future_entries)}", ""]
            for entry in future_entries[:10]:
                evidence.append(
                    f"  {entry.key_path}\\{entry.value_name}: {entry.last_write}"
                )

            self.add_finding(Finding(
                title="Registry Keys with Future Timestamps",
                description=(
                    f"Found {len(future_entries)} registry keys with LastWrite timestamps "
                    f"in the future. This indicates timestamp manipulation or system clock "
                    f"tampering at the time the keys were modified."
                ),
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=evidence,
                recommendation="Check system clock sync history and correlate with other timestamp anomalies.",
            ))

        # Check for clustered timestamps (batch modification)
        if self.config.incident_start and self.config.incident_end:
            incident_mods = [
                e for e in ts_entries
                if self.config.incident_start <= e.last_write <= self.config.incident_end
            ]
            if len(incident_mods) > 20:
                evidence = [
                    f"Registry keys modified during incident window: {len(incident_mods)}",
                    f"Window: {self.config.incident_start} to {self.config.incident_end}",
                    "",
                ]
                for entry in incident_mods[:15]:
                    evidence.append(
                        f"  {entry.key_path}\\{entry.value_name} at {entry.last_write}"
                    )

                self.add_finding(Finding(
                    title="Heavy Registry Modification During Incident Window",
                    description=(
                        f"Found {len(incident_mods)} registry keys modified during the "
                        f"incident time window. High volume of registry changes during an "
                        f"incident may indicate attacker configuration changes, persistence "
                        f"setup, or anti-forensic cleanup."
                    ),
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence,
                    timestamp=incident_mods[0].last_write,
                    recommendation="Review each modified key for security relevance.",
                ))

    def _check_antiforensic_artifacts(self, entries: List[RegistryEntry]):
        """Check for registry artifacts of known anti-forensic tools."""
        tool_artifacts = {
            "piriform": "CCleaner",
            "ccleaner": "CCleaner",
            "bleachbit": "BleachBit",
            "eraser": "Eraser secure deletion",
            "bcwipe": "BCWipe",
            "sdelete": "SDelete",
        }

        found = []
        for entry in entries:
            key_lower = entry.key_path.lower()
            value_lower = (entry.value_data or "").lower()

            for pattern, tool_name in tool_artifacts.items():
                if pattern in key_lower or pattern in value_lower:
                    found.append((entry, tool_name))
                    break

        if not found:
            return

        evidence = [f"Anti-forensic tool registry artifacts: {len(found)}", ""]
        for entry, tool_name in found[:15]:
            evidence.append(
                f"  {tool_name}: {entry.key_path}\\{entry.value_name} = {entry.value_data[:100]}"
            )

        self.add_finding(Finding(
            title="Anti-Forensic Tool Registry Artifacts Found",
            description=(
                f"Found {len(found)} registry entries associated with known anti-forensic "
                f"tools. These artifacts persist even after the tool is uninstalled, "
                f"confirming the tool was installed and used on this system."
            ),
            category=self.category,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence=evidence,
            recommendation=(
                "Determine when these tools were installed and last used. "
                "Cross-reference with Prefetch and Amcache for execution timestamps."
            ),
        ))

    def _check_persistence_remnants(self, entries: List[RegistryEntry]):
        """Detect partially cleaned persistence mechanisms."""
        persistence_entries = []

        for entry in entries:
            key_lower = entry.key_path.lower()
            for loc in PERSISTENCE_LOCATIONS:
                if loc.lower().lstrip("hklm\\").lstrip("hkcu\\") in key_lower:
                    if entry.value_data:
                        persistence_entries.append(entry)
                    break

        if not persistence_entries:
            return

        # Check for suspicious values (paths to temp, non-standard locations)
        suspicious_persistence = []
        for entry in persistence_entries:
            value_lower = entry.value_data.lower()
            suspicious_indicators = [
                "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                "\\programdata\\", "\\users\\public\\",
                "powershell", "cmd.exe /c", "wscript", "cscript",
                "mshta", "rundll32", "regsvr32",
                ".ps1", ".vbs", ".js", ".hta", ".bat",
            ]
            for indicator in suspicious_indicators:
                if indicator in value_lower:
                    suspicious_persistence.append((entry, indicator))
                    break

        if suspicious_persistence:
            evidence = [
                f"Suspicious persistence entries: {len(suspicious_persistence)}",
                "",
            ]
            for entry, indicator in suspicious_persistence[:10]:
                evidence.append(
                    f"  {entry.key_path}\\{entry.value_name}"
                )
                evidence.append(
                    f"    Value: {entry.value_data[:200]}"
                )
                evidence.append(f"    Indicator: {indicator}")

            self.add_finding(Finding(
                title="Suspicious Persistence Mechanisms Detected",
                description=(
                    f"Found {len(suspicious_persistence)} suspicious persistence entries in "
                    f"autorun registry locations. These entries reference scripts, temp directories, "
                    f"or LOLBins, which are typical of attacker persistence mechanisms."
                ),
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=evidence,
                recommendation=(
                    "Investigate each persistence entry. Check if the referenced file still exists. "
                    "Cross-reference with Prefetch/Amcache for execution evidence. "
                    "Determine if these are legitimate or attacker-created."
                ),
            ))

    def _check_usn_journal_config(self, entries: List[RegistryEntry]):
        """Check for USN Journal configuration changes."""
        for entry in entries:
            if "usnjrnl" in entry.key_path.lower() or "usnjournal" in entry.key_path.lower():
                self.add_finding(Finding(
                    title="USN Journal Configuration Modified",
                    description=(
                        f"Registry entry related to USN Journal configuration was found: "
                        f"{entry.key_path}. Modification of USN Journal settings can be used "
                        f"to limit the size of the journal or disable it entirely."
                    ),
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=[
                        f"Key: {entry.key_path}",
                        f"Value: {entry.value_name} = {entry.value_data}",
                        f"Last write: {entry.last_write}",
                    ],
                    timestamp=entry.last_write,
                    recommendation="Verify USN Journal is active and has adequate maximum size.",
                ))
                break  # Only report once
