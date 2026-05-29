"""
USN (Update Sequence Number) Journal parser.
Supports UsnJrnl CSV output from MFTECmd and raw $UsnJrnl:$J binary.
"""

import csv
import os
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from canary.parsers.mft_parser import filetime_to_datetime

# USN record version constants
USN_RECORD_V2 = 2
USN_RECORD_V3 = 3

# USN reason flags
USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}


class UsnRecord:
    """Represents a single USN Journal record."""

    __slots__ = [
        "usn",
        "timestamp",
        "filename",
        "mft_entry",
        "mft_sequence",
        "parent_entry",
        "parent_sequence",
        "reason_flags",
        "reasons",
        "file_attributes",
        "source_info",
    ]

    def __init__(self):
        self.usn: int = 0
        self.timestamp: Optional[datetime] = None
        self.filename: str = ""
        self.mft_entry: int = 0
        self.mft_sequence: int = 0
        self.parent_entry: int = 0
        self.parent_sequence: int = 0
        self.reason_flags: int = 0
        self.reasons: List[str] = []
        self.file_attributes: int = 0
        self.source_info: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "usn": self.usn,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "filename": self.filename,
            "mft_entry": self.mft_entry,
            "mft_sequence": self.mft_sequence,
            "parent_entry": self.parent_entry,
            "parent_sequence": self.parent_sequence,
            "reasons": self.reasons,
            "reason_flags": hex(self.reason_flags),
        }

    @property
    def is_file_create(self) -> bool:
        return bool(self.reason_flags & 0x00000100)

    @property
    def is_file_delete(self) -> bool:
        return bool(self.reason_flags & 0x00000200)

    @property
    def is_rename(self) -> bool:
        return bool(self.reason_flags & (0x00001000 | 0x00002000))

    @property
    def is_data_change(self) -> bool:
        return bool(self.reason_flags & (0x00000001 | 0x00000002 | 0x00000004))

    @property
    def is_close(self) -> bool:
        return bool(self.reason_flags & 0x80000000)

    @property
    def is_security_change(self) -> bool:
        return bool(self.reason_flags & 0x00000800)


def decode_reason_flags(flags: int) -> List[str]:
    """Decode USN reason flags into human-readable strings."""
    reasons = []
    for flag, name in USN_REASONS.items():
        if flags & flag:
            reasons.append(name)
    return reasons


class UsnParser:
    """
    Parser for NTFS USN Journal data.
    Supports:
    - MFTECmd $J CSV output
    - Raw $UsnJrnl:$J binary file
    - Generic CSV with USN columns
    """

    def __init__(self):
        self._records: List[UsnRecord] = []

    @property
    def records(self) -> List[UsnRecord]:
        return self._records

    @property
    def record_count(self) -> int:
        return len(self._records)

    def parse(self, path: str) -> List[UsnRecord]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        ext = Path(path).suffix.lower()
        if ext == ".csv":
            records = list(self._parse_csv(path))
        elif ext in (".bin", ".raw", ""):
            records = list(self._parse_raw(path))
        else:
            try:
                records = list(self._parse_csv(path))
            except Exception:
                records = list(self._parse_raw(path))

        self._records.extend(records)
        self._records.sort(key=lambda r: r.usn)
        return records

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp from CSV."""
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

    def _parse_csv(self, path: str) -> Generator[UsnRecord, None, None]:
        """Parse MFTECmd $J CSV output."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    record = UsnRecord()

                    # USN offset
                    usn_str = row.get("UpdateSequenceNumber", row.get("USN", row.get("usn", "0")))
                    record.usn = int(usn_str) if usn_str else 0

                    # Timestamp
                    ts_str = row.get("UpdateTimestamp", row.get("Timestamp", row.get("timestamp", "")))
                    record.timestamp = self._parse_timestamp(ts_str)

                    # Filename
                    record.filename = row.get("Name", row.get("FileName", row.get("filename", "")))

                    # MFT reference
                    entry_str = row.get("EntryNumber", row.get("MFTEntry", row.get("entry_number", "0")))
                    record.mft_entry = int(entry_str) if entry_str else 0

                    seq_str = row.get("SequenceNumber", row.get("MFTSequence", row.get("sequence", "0")))
                    record.mft_sequence = int(seq_str) if seq_str else 0

                    # Parent reference
                    parent_entry = row.get("ParentEntryNumber", row.get("ParentEntry", "0"))
                    record.parent_entry = int(parent_entry) if parent_entry else 0

                    parent_seq = row.get("ParentSequenceNumber", row.get("ParentSequence", "0"))
                    record.parent_sequence = int(parent_seq) if parent_seq else 0

                    # Reason flags
                    reason_str = row.get("UpdateReasons", row.get("Reason", row.get("reasons", "")))
                    if reason_str:
                        if reason_str.startswith("0x"):
                            record.reason_flags = int(reason_str, 16)
                        elif reason_str.isdigit():
                            record.reason_flags = int(reason_str)
                        else:
                            # Parse comma-separated reason names
                            record.reasons = [r.strip() for r in reason_str.split(",")]
                            # Reverse-map to flags
                            name_to_flag = {v: k for k, v in USN_REASONS.items()}
                            for reason_name in record.reasons:
                                flag = name_to_flag.get(reason_name.upper().replace(" ", "_"), 0)
                                record.reason_flags |= flag

                    if not record.reasons:
                        record.reasons = decode_reason_flags(record.reason_flags)

                    yield record
                except (ValueError, KeyError):
                    continue

    def _parse_raw(self, path: str) -> Generator[UsnRecord, None, None]:
        """Parse raw $UsnJrnl:$J binary data."""
        file_size = os.path.getsize(path)
        with open(path, "rb") as f:
            offset = 0
            # Skip leading zeros (sparse file)
            chunk_size = 65536
            while offset < file_size:
                f.seek(offset)
                chunk = f.read(chunk_size)
                if chunk != b"\x00" * len(chunk):
                    break
                offset += chunk_size

            while offset < file_size:
                f.seek(offset)
                header = f.read(4)
                if len(header) < 4:
                    break

                record_len = struct.unpack_from("<I", header, 0)[0]
                if record_len == 0:
                    offset += 8  # Skip zero-length records (padding)
                    continue

                if record_len < 60 or record_len > 65536:
                    offset += 8
                    continue

                f.seek(offset)
                record_data = f.read(record_len)
                if len(record_data) < record_len:
                    break

                try:
                    record = self._parse_usn_v2_record(record_data, offset)
                    if record:
                        yield record
                except Exception:
                    pass

                offset += record_len
                # Align to 8 bytes
                if offset % 8:
                    offset += 8 - (offset % 8)

    def _parse_usn_v2_record(self, data: bytes, file_offset: int) -> Optional[UsnRecord]:
        """Parse a single USN V2 record from binary data."""
        if len(data) < 60:
            return None

        record = UsnRecord()

        record_len = struct.unpack_from("<I", data, 0)[0]
        major_version = struct.unpack_from("<H", data, 4)[0]

        if major_version not in (2, 3):
            return None

        # MFT reference (8 bytes at offset 8)
        mft_ref = struct.unpack_from("<Q", data, 8)[0]
        record.mft_entry = mft_ref & 0x0000FFFFFFFFFFFF
        record.mft_sequence = (mft_ref >> 48) & 0xFFFF

        # Parent reference (8 bytes at offset 16)
        parent_ref = struct.unpack_from("<Q", data, 16)[0]
        record.parent_entry = parent_ref & 0x0000FFFFFFFFFFFF
        record.parent_sequence = (parent_ref >> 48) & 0xFFFF

        # USN (8 bytes at offset 24)
        record.usn = struct.unpack_from("<Q", data, 24)[0]

        # Timestamp (8 bytes at offset 32)
        filetime = struct.unpack_from("<Q", data, 32)[0]
        record.timestamp = filetime_to_datetime(filetime)

        # Reason flags (4 bytes at offset 40)
        record.reason_flags = struct.unpack_from("<I", data, 40)[0]
        record.reasons = decode_reason_flags(record.reason_flags)

        # Source info (4 bytes at offset 44)
        record.source_info = struct.unpack_from("<I", data, 44)[0]

        # File attributes (4 bytes at offset 52)
        record.file_attributes = struct.unpack_from("<I", data, 52)[0]

        # Filename (variable length)
        name_length = struct.unpack_from("<H", data, 56)[0]
        name_offset = struct.unpack_from("<H", data, 58)[0]

        if name_offset + name_length <= len(data):
            try:
                record.filename = data[name_offset: name_offset + name_length].decode("utf-16-le")
            except UnicodeDecodeError:
                record.filename = f"<usn_{record.usn}>"

        return record

    def get_records_by_mft_entry(self, entry_number: int) -> List[UsnRecord]:
        return [r for r in self._records if r.mft_entry == entry_number]

    def get_file_deletions(self) -> List[UsnRecord]:
        return [r for r in self._records if r.is_file_delete]

    def get_file_creations(self) -> List[UsnRecord]:
        return [r for r in self._records if r.is_file_create]

    def get_renames(self) -> List[UsnRecord]:
        return [r for r in self._records if r.is_rename]

    def get_records_in_range(self, start: datetime, end: datetime) -> List[UsnRecord]:
        return [
            r for r in self._records
            if r.timestamp and start <= r.timestamp <= end
        ]

    def clear(self):
        self._records.clear()
