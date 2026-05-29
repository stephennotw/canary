"""
EVTX log parser - supports both live .evtx files and pre-exported JSON/CSV.
Uses python-evtx for direct parsing, falls back to JSON/XML import.
"""

import csv
import json
import os
import struct
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

# Record header signature for EVTX
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"
EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"


class EvtxRecord:
    """Represents a single Windows Event Log record."""

    __slots__ = [
        "record_id",
        "event_id",
        "timestamp",
        "provider",
        "channel",
        "computer",
        "level",
        "user_sid",
        "data",
        "raw_xml",
    ]

    def __init__(
        self,
        record_id: int = 0,
        event_id: int = 0,
        timestamp: Optional[datetime] = None,
        provider: str = "",
        channel: str = "",
        computer: str = "",
        level: int = 0,
        user_sid: str = "",
        data: Optional[Dict[str, Any]] = None,
        raw_xml: str = "",
    ):
        self.record_id = record_id
        self.event_id = event_id
        self.timestamp = timestamp
        self.provider = provider
        self.channel = channel
        self.computer = computer
        self.level = level
        self.user_sid = user_sid
        self.data = data or {}
        self.raw_xml = raw_xml

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "provider": self.provider,
            "channel": self.channel,
            "computer": self.computer,
            "level": self.level,
            "user_sid": self.user_sid,
            "data": self.data,
        }


class EvtxParser:
    """
    Parser for Windows Event Log files.
    Supports:
    - Live .evtx files (binary parsing)
    - Pre-exported JSON (EvtxECmd JSON output)
    - Pre-exported CSV (EvtxECmd CSV output)
    - XML export from Event Viewer
    """

    def __init__(self):
        self._records: List[EvtxRecord] = []
        self._source_files: List[str] = []

    @property
    def records(self) -> List[EvtxRecord]:
        return self._records

    @property
    def record_count(self) -> int:
        return len(self._records)

    def parse(self, path: str) -> List[EvtxRecord]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        self._source_files.append(path)
        ext = Path(path).suffix.lower()

        if ext == ".evtx":
            records = list(self._parse_evtx_binary(path))
        elif ext == ".json" or ext == ".jsonl":
            records = list(self._parse_json(path))
        elif ext == ".csv":
            records = list(self._parse_csv(path))
        elif ext == ".xml":
            records = list(self._parse_xml(path))
        else:
            # Try JSON first, then CSV
            try:
                records = list(self._parse_json(path))
            except (json.JSONDecodeError, UnicodeDecodeError):
                records = list(self._parse_csv(path))

        self._records.extend(records)
        self._records.sort(key=lambda r: (r.timestamp or datetime.min, r.record_id))
        return records

    def parse_directory(self, dir_path: str, extensions: Optional[List[str]] = None) -> List[EvtxRecord]:
        """Parse all supported files in a directory."""
        if extensions is None:
            extensions = [".evtx", ".json", ".jsonl", ".csv", ".xml"]
        all_records = []
        for root, _dirs, files in os.walk(dir_path):
            for fname in sorted(files):
                if Path(fname).suffix.lower() in extensions:
                    fpath = os.path.join(root, fname)
                    try:
                        records = self.parse(fpath)
                        all_records.extend(records)
                    except Exception:
                        continue
        return all_records

    def _parse_evtx_binary(self, path: str) -> Generator[EvtxRecord, None, None]:
        """Parse a binary .evtx file using pure Python."""
        try:
            import evtx as python_evtx
            yield from self._parse_with_python_evtx(path)
            return
        except ImportError:
            pass

        # Fallback: pure Python binary parsing
        yield from self._parse_evtx_raw(path)

    def _parse_with_python_evtx(self, path: str) -> Generator[EvtxRecord, None, None]:
        """Parse using python-evtx library if available."""
        import evtx

        with evtx.Evtx(path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    rec = self._xml_string_to_record(xml_str, record.record_num())
                    if rec:
                        yield rec
                except Exception:
                    continue

    def _parse_evtx_raw(self, path: str) -> Generator[EvtxRecord, None, None]:
        """
        Raw binary EVTX parser - reads chunk and record headers to extract
        record IDs and basic metadata. Used when python-evtx is not available.
        """
        with open(path, "rb") as f:
            header = f.read(4096)
            if not header[:8] == EVTX_FILE_MAGIC:
                return

            # Read chunks
            while True:
                chunk_header = f.read(512)
                if len(chunk_header) < 512:
                    break
                if chunk_header[:8] != EVTX_CHUNK_MAGIC:
                    # Try to find next chunk
                    f.seek(f.tell() - 512 + 65536)
                    continue

                first_record_id = struct.unpack_from("<Q", chunk_header, 40)[0]
                last_record_id = struct.unpack_from("<Q", chunk_header, 48)[0]

                # Read rest of chunk (65536 - 512 already read)
                chunk_data = chunk_header + f.read(65536 - 512)

                offset = 512
                while offset < len(chunk_data) - 28:
                    if chunk_data[offset : offset + 4] != EVTX_RECORD_MAGIC:
                        offset += 1
                        continue

                    try:
                        rec_size = struct.unpack_from("<I", chunk_data, offset + 4)[0]
                        rec_id = struct.unpack_from("<Q", chunk_data, offset + 8)[0]
                        ts_val = struct.unpack_from("<Q", chunk_data, offset + 16)[0]

                        # Convert Windows FILETIME to datetime
                        if ts_val > 0:
                            epoch_diff = 116444736000000000
                            ts_micro = (ts_val - epoch_diff) / 10
                            try:
                                timestamp = datetime(1970, 1, 1) + __import__(
                                    "datetime"
                                ).timedelta(microseconds=ts_micro)
                            except (ValueError, OverflowError):
                                timestamp = None
                        else:
                            timestamp = None

                        yield EvtxRecord(
                            record_id=rec_id,
                            timestamp=timestamp,
                        )

                        offset += max(rec_size, 8)
                    except (struct.error, ValueError):
                        offset += 4

    def _xml_string_to_record(self, xml_str: str, record_num: int = 0) -> Optional[EvtxRecord]:
        """Parse an XML event record string into an EvtxRecord."""
        try:
            # Handle namespace
            xml_str_clean = xml_str.replace(
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ""
            )
            root = ET.fromstring(xml_str_clean)

            system = root.find("System")
            if system is None:
                return None

            event_id_elem = system.find("EventID")
            event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

            time_elem = system.find("TimeCreated")
            timestamp = None
            if time_elem is not None:
                ts_str = time_elem.get("SystemTime", "")
                if ts_str:
                    for fmt in [
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S.%f",
                        "%Y-%m-%d %H:%M:%S",
                    ]:
                        try:
                            timestamp = datetime.strptime(ts_str[:26].rstrip("Z") + "Z" if "Z" in ts_str else ts_str[:26], fmt)
                            break
                        except ValueError:
                            continue
                    if timestamp is None:
                        try:
                            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace("+00:00", ""))
                        except (ValueError, AttributeError):
                            pass

            provider_elem = system.find("Provider")
            provider = provider_elem.get("Name", "") if provider_elem is not None else ""

            channel_elem = system.find("Channel")
            channel = channel_elem.text if channel_elem is not None and channel_elem.text else ""

            computer_elem = system.find("Computer")
            computer = computer_elem.text if computer_elem is not None and computer_elem.text else ""

            level_elem = system.find("Level")
            level = int(level_elem.text) if level_elem is not None and level_elem.text else 0

            record_id_elem = system.find("EventRecordID")
            record_id = int(record_id_elem.text) if record_id_elem is not None and record_id_elem.text else record_num

            security_elem = system.find("Security")
            user_sid = security_elem.get("UserID", "") if security_elem is not None else ""

            # Extract EventData
            data = {}
            event_data = root.find("EventData")
            if event_data is not None:
                for d in event_data.findall("Data"):
                    name = d.get("Name", "")
                    value = d.text or ""
                    if name:
                        data[name] = value

            return EvtxRecord(
                record_id=record_id,
                event_id=event_id,
                timestamp=timestamp,
                provider=provider,
                channel=channel,
                computer=computer,
                level=level,
                user_sid=user_sid,
                data=data,
                raw_xml=xml_str,
            )
        except ET.ParseError:
            return None

    def _parse_json(self, path: str) -> Generator[EvtxRecord, None, None]:
        """Parse JSON/JSONL output (e.g., from EvtxECmd)."""
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read().strip()

        # Try JSONL (one record per line)
        if content.startswith("{"):
            lines = content.split("\n")
            for line in lines:
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    yield self._json_obj_to_record(obj)
                except (json.JSONDecodeError, KeyError):
                    continue
        # Try JSON array
        elif content.startswith("["):
            try:
                records = json.loads(content)
                for obj in records:
                    try:
                        yield self._json_obj_to_record(obj)
                    except KeyError:
                        continue
            except json.JSONDecodeError:
                pass

    def _json_obj_to_record(self, obj: Dict[str, Any]) -> EvtxRecord:
        """Convert a JSON object to an EvtxRecord. Handles multiple JSON schemas."""
        # EvtxECmd format
        record_id = int(obj.get("RecordNumber", obj.get("EventRecordID", obj.get("record_id", 0))))
        event_id = int(obj.get("EventId", obj.get("EventID", obj.get("event_id", 0))))

        ts_str = obj.get("TimeCreated", obj.get("Timestamp", obj.get("timestamp", "")))
        timestamp = None
        if ts_str:
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    clean = str(ts_str).replace("Z", "").replace("+00:00", "")[:26]
                    timestamp = datetime.strptime(clean, fmt)
                    break
                except ValueError:
                    continue

        provider = str(obj.get("Provider", obj.get("SourceName", obj.get("provider", ""))))
        channel = str(obj.get("Channel", obj.get("LogName", obj.get("channel", ""))))
        computer = str(obj.get("Computer", obj.get("MachineName", obj.get("computer", ""))))
        level = int(obj.get("Level", obj.get("level", 0)))
        user_sid = str(obj.get("UserId", obj.get("UserSid", obj.get("user_sid", ""))))

        # Extract event data from various possible locations
        data = {}
        if "EventData" in obj and isinstance(obj["EventData"], dict):
            data = obj["EventData"]
        elif "PayloadData1" in obj:
            # EvtxECmd flattened format
            for k, v in obj.items():
                if k.startswith("PayloadData") or k.startswith("Payload"):
                    data[k] = v
        for key in ["SubjectUserName", "TargetUserName", "ProcessName", "IpAddress",
                     "LogonType", "CommandLine", "ParentProcessName", "Image",
                     "ParentImage", "TargetFilename"]:
            if key in obj:
                data[key] = obj[key]

        return EvtxRecord(
            record_id=record_id,
            event_id=event_id,
            timestamp=timestamp,
            provider=provider,
            channel=channel,
            computer=computer,
            level=level,
            user_sid=user_sid,
            data=data,
        )

    def _parse_csv(self, path: str) -> Generator[EvtxRecord, None, None]:
        """Parse CSV output (e.g., from EvtxECmd or custom export)."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    yield self._json_obj_to_record(dict(row))
                except (KeyError, ValueError):
                    continue

    def _parse_xml(self, path: str) -> Generator[EvtxRecord, None, None]:
        """Parse XML export from Event Viewer."""
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            # Handle namespace
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event in root.iter():
                if event.tag.endswith("Event") or event.tag == "{http://schemas.microsoft.com/win/2004/08/events/event}Event":
                    xml_str = ET.tostring(event, encoding="unicode")
                    rec = self._xml_string_to_record(xml_str)
                    if rec:
                        yield rec
        except ET.ParseError:
            pass

    def get_records_by_event_id(self, event_id: int) -> List[EvtxRecord]:
        return [r for r in self._records if r.event_id == event_id]

    def get_records_in_range(
        self, start: datetime, end: datetime
    ) -> List[EvtxRecord]:
        return [
            r
            for r in self._records
            if r.timestamp and start <= r.timestamp <= end
        ]

    def get_record_ids(self) -> List[int]:
        return sorted(set(r.record_id for r in self._records if r.record_id > 0))

    def get_channels(self) -> List[str]:
        return sorted(set(r.channel for r in self._records if r.channel))

    def clear(self):
        self._records.clear()
        self._source_files.clear()
