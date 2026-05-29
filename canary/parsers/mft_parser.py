"""
MFT (Master File Table) parser.
Supports MFTECmd CSV output and raw MFT binary parsing.
Extracts $STANDARD_INFORMATION and $FILE_NAME timestamps for timestomping detection.
"""

import csv
import os
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


# MFT record constants
MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024
ATTRIBUTE_SI = 0x10  # $STANDARD_INFORMATION
ATTRIBUTE_FN = 0x30  # $FILE_NAME
ATTRIBUTE_END = 0xFFFFFFFF

# Windows FILETIME epoch diff (100-nanosecond intervals since 1601-01-01)
EPOCH_DIFF = 116444736000000000


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to Python datetime."""
    if filetime <= 0 or filetime < EPOCH_DIFF:
        return None
    try:
        microseconds = (filetime - EPOCH_DIFF) // 10
        return datetime(1970, 1, 1) + timedelta(microseconds=microseconds)
    except (ValueError, OverflowError, OSError):
        return None


class MftEntry:
    """Represents a single MFT record with both $SI and $FN timestamps."""

    __slots__ = [
        "entry_number",
        "sequence_number",
        "parent_entry",
        "parent_sequence",
        "filename",
        "full_path",
        "in_use",
        "is_directory",
        "file_size",
        # $STANDARD_INFORMATION timestamps
        "si_created",
        "si_modified",
        "si_entry_modified",
        "si_accessed",
        # $FILE_NAME timestamps
        "fn_created",
        "fn_modified",
        "fn_entry_modified",
        "fn_accessed",
        # Flags
        "has_ads",
        "is_resident",
    ]

    def __init__(self):
        self.entry_number: int = 0
        self.sequence_number: int = 0
        self.parent_entry: int = 0
        self.parent_sequence: int = 0
        self.filename: str = ""
        self.full_path: str = ""
        self.in_use: bool = True
        self.is_directory: bool = False
        self.file_size: int = 0
        self.si_created: Optional[datetime] = None
        self.si_modified: Optional[datetime] = None
        self.si_entry_modified: Optional[datetime] = None
        self.si_accessed: Optional[datetime] = None
        self.fn_created: Optional[datetime] = None
        self.fn_modified: Optional[datetime] = None
        self.fn_entry_modified: Optional[datetime] = None
        self.fn_accessed: Optional[datetime] = None
        self.has_ads: bool = False
        self.is_resident: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_number": self.entry_number,
            "sequence_number": self.sequence_number,
            "parent_entry": self.parent_entry,
            "filename": self.filename,
            "full_path": self.full_path,
            "in_use": self.in_use,
            "is_directory": self.is_directory,
            "file_size": self.file_size,
            "si_created": self.si_created.isoformat() if self.si_created else None,
            "si_modified": self.si_modified.isoformat() if self.si_modified else None,
            "si_entry_modified": self.si_entry_modified.isoformat() if self.si_entry_modified else None,
            "si_accessed": self.si_accessed.isoformat() if self.si_accessed else None,
            "fn_created": self.fn_created.isoformat() if self.fn_created else None,
            "fn_modified": self.fn_modified.isoformat() if self.fn_modified else None,
            "fn_entry_modified": self.fn_entry_modified.isoformat() if self.fn_entry_modified else None,
            "fn_accessed": self.fn_accessed.isoformat() if self.fn_accessed else None,
        }


class MftParser:
    """
    Parser for NTFS Master File Table data.
    Supports:
    - MFTECmd CSV output (primary recommended format)
    - Raw $MFT binary file
    - Generic CSV with timestamp columns
    """

    def __init__(self):
        self._entries: List[MftEntry] = []
        self._path_map: Dict[int, MftEntry] = {}

    @property
    def entries(self) -> List[MftEntry]:
        return self._entries

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def parse(self, path: str) -> List[MftEntry]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        ext = Path(path).suffix.lower()
        if ext == ".csv":
            entries = list(self._parse_mftecmd_csv(path))
        elif ext in (".bin", ".raw", ""):
            entries = list(self._parse_raw_mft(path))
        else:
            # Try CSV first
            try:
                entries = list(self._parse_mftecmd_csv(path))
            except Exception:
                entries = list(self._parse_raw_mft(path))

        self._entries.extend(entries)
        for entry in entries:
            self._path_map[entry.entry_number] = entry
        return entries

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp from various CSV formats."""
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
        try:
            return datetime.fromisoformat(ts_str.replace("Z", ""))
        except (ValueError, AttributeError):
            return None

    def _parse_mftecmd_csv(self, path: str) -> Generator[MftEntry, None, None]:
        """Parse MFTECmd CSV output."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []

            # Detect MFTECmd vs generic format by checking column names
            is_mftecmd = any(
                h in headers
                for h in ["EntryNumber", "SequenceNumber", "Created0x10"]
            )

            for row in reader:
                entry = MftEntry()
                try:
                    if is_mftecmd:
                        entry = self._parse_mftecmd_row(row)
                    else:
                        entry = self._parse_generic_csv_row(row, headers)
                    if entry.entry_number >= 0:
                        yield entry
                except (ValueError, KeyError):
                    continue

    def _parse_mftecmd_row(self, row: Dict[str, str]) -> MftEntry:
        """Parse a single MFTECmd CSV row."""
        entry = MftEntry()
        entry.entry_number = int(row.get("EntryNumber", 0))
        entry.sequence_number = int(row.get("SequenceNumber", 0))

        parent_path = row.get("ParentPath", "")
        filename = row.get("FileName", "")
        entry.filename = filename
        entry.full_path = f"{parent_path}\\{filename}" if parent_path else filename

        entry.in_use = row.get("InUse", "True").lower() == "true"
        entry.is_directory = row.get("IsDirectory", "False").lower() == "true"

        parent_entry = row.get("ParentEntryNumber", "0")
        entry.parent_entry = int(parent_entry) if parent_entry else 0
        parent_seq = row.get("ParentSequenceNumber", "0")
        entry.parent_sequence = int(parent_seq) if parent_seq else 0

        file_size = row.get("FileSize", "0")
        entry.file_size = int(file_size) if file_size else 0

        # $STANDARD_INFORMATION timestamps (0x10)
        entry.si_created = self._parse_timestamp(row.get("Created0x10", ""))
        entry.si_modified = self._parse_timestamp(row.get("LastModified0x10", ""))
        entry.si_entry_modified = self._parse_timestamp(row.get("LastRecordChange0x10", ""))
        entry.si_accessed = self._parse_timestamp(row.get("LastAccess0x10", ""))

        # $FILE_NAME timestamps (0x30)
        entry.fn_created = self._parse_timestamp(row.get("Created0x30", ""))
        entry.fn_modified = self._parse_timestamp(row.get("LastModified0x30", ""))
        entry.fn_entry_modified = self._parse_timestamp(row.get("LastRecordChange0x30", ""))
        entry.fn_accessed = self._parse_timestamp(row.get("LastAccess0x30", ""))

        entry.has_ads = row.get("HasAds", "False").lower() == "true"

        return entry

    def _parse_generic_csv_row(self, row: Dict[str, str], headers: List[str]) -> MftEntry:
        """Parse a generic CSV row with flexible column name matching."""
        entry = MftEntry()

        # Try common column names for entry number
        for col in ["EntryNumber", "entry_number", "MFTEntryNumber", "Record", "RecordNumber"]:
            if col in row:
                entry.entry_number = int(row[col] or 0)
                break

        # Filename
        for col in ["FileName", "filename", "Name", "File"]:
            if col in row:
                entry.filename = row[col] or ""
                break

        # Full path
        for col in ["FullPath", "full_path", "Path", "FilePath"]:
            if col in row:
                entry.full_path = row[col] or ""
                break
        if not entry.full_path:
            entry.full_path = entry.filename

        # In use
        for col in ["InUse", "in_use", "Active", "Allocated"]:
            if col in row:
                entry.in_use = row[col].lower() in ("true", "1", "yes")
                break

        # $SI timestamps
        si_ts_names = {
            "si_created": ["Created0x10", "SI_Created", "si_created", "CreatedTimestamp"],
            "si_modified": ["LastModified0x10", "SI_Modified", "si_modified", "ModifiedTimestamp"],
            "si_entry_modified": ["LastRecordChange0x10", "SI_EntryModified", "si_entry_modified"],
            "si_accessed": ["LastAccess0x10", "SI_Accessed", "si_accessed", "AccessedTimestamp"],
        }
        for attr, candidates in si_ts_names.items():
            for col in candidates:
                if col in row and row[col]:
                    setattr(entry, attr, self._parse_timestamp(row[col]))
                    break

        # $FN timestamps
        fn_ts_names = {
            "fn_created": ["Created0x30", "FN_Created", "fn_created"],
            "fn_modified": ["LastModified0x30", "FN_Modified", "fn_modified"],
            "fn_entry_modified": ["LastRecordChange0x30", "FN_EntryModified", "fn_entry_modified"],
            "fn_accessed": ["LastAccess0x30", "FN_Accessed", "fn_accessed"],
        }
        for attr, candidates in fn_ts_names.items():
            for col in candidates:
                if col in row and row[col]:
                    setattr(entry, attr, self._parse_timestamp(row[col]))
                    break

        return entry

    def _parse_raw_mft(self, path: str) -> Generator[MftEntry, None, None]:
        """Parse a raw $MFT binary file."""
        file_size = os.path.getsize(path)
        with open(path, "rb") as f:
            offset = 0
            while offset < file_size:
                f.seek(offset)
                record_data = f.read(MFT_RECORD_SIZE)
                if len(record_data) < MFT_RECORD_SIZE:
                    break

                if record_data[:4] != MFT_RECORD_MAGIC:
                    offset += MFT_RECORD_SIZE
                    continue

                try:
                    entry = self._parse_mft_record(record_data, offset // MFT_RECORD_SIZE)
                    if entry:
                        yield entry
                except Exception:
                    pass

                offset += MFT_RECORD_SIZE

    def _parse_mft_record(self, data: bytes, record_num: int) -> Optional[MftEntry]:
        """Parse a single raw MFT record."""
        if len(data) < 56:
            return None

        entry = MftEntry()
        entry.entry_number = record_num

        # Flags at offset 22
        flags = struct.unpack_from("<H", data, 22)[0]
        entry.in_use = bool(flags & 0x01)
        entry.is_directory = bool(flags & 0x02)

        # Sequence number at offset 16
        entry.sequence_number = struct.unpack_from("<H", data, 16)[0]

        # First attribute offset at offset 20
        attr_offset = struct.unpack_from("<H", data, 20)[0]

        # Walk attributes
        while attr_offset < len(data) - 16:
            attr_type = struct.unpack_from("<I", data, attr_offset)[0]
            if attr_type == ATTRIBUTE_END or attr_type == 0:
                break

            attr_len = struct.unpack_from("<I", data, attr_offset + 4)[0]
            if attr_len == 0 or attr_len > len(data) - attr_offset:
                break

            if attr_type == ATTRIBUTE_SI:
                self._parse_si_attribute(data, attr_offset, entry)
            elif attr_type == ATTRIBUTE_FN:
                self._parse_fn_attribute(data, attr_offset, entry)

            attr_offset += attr_len

        return entry

    def _parse_si_attribute(self, data: bytes, attr_offset: int, entry: MftEntry):
        """Parse $STANDARD_INFORMATION attribute timestamps."""
        non_resident = data[attr_offset + 8]
        if non_resident:
            return

        content_offset = struct.unpack_from("<H", data, attr_offset + 20)[0]
        si_offset = attr_offset + content_offset

        if si_offset + 32 > len(data):
            return

        entry.si_created = filetime_to_datetime(struct.unpack_from("<Q", data, si_offset)[0])
        entry.si_modified = filetime_to_datetime(struct.unpack_from("<Q", data, si_offset + 8)[0])
        entry.si_entry_modified = filetime_to_datetime(struct.unpack_from("<Q", data, si_offset + 16)[0])
        entry.si_accessed = filetime_to_datetime(struct.unpack_from("<Q", data, si_offset + 24)[0])

    def _parse_fn_attribute(self, data: bytes, attr_offset: int, entry: MftEntry):
        """Parse $FILE_NAME attribute timestamps and filename."""
        non_resident = data[attr_offset + 8]
        if non_resident:
            return

        content_offset = struct.unpack_from("<H", data, attr_offset + 20)[0]
        fn_offset = attr_offset + content_offset

        if fn_offset + 66 > len(data):
            return

        # Parent directory reference
        parent_ref = struct.unpack_from("<Q", data, fn_offset)[0]
        entry.parent_entry = parent_ref & 0x0000FFFFFFFFFFFF
        entry.parent_sequence = (parent_ref >> 48) & 0xFFFF

        # Timestamps
        entry.fn_created = filetime_to_datetime(struct.unpack_from("<Q", data, fn_offset + 8)[0])
        entry.fn_modified = filetime_to_datetime(struct.unpack_from("<Q", data, fn_offset + 16)[0])
        entry.fn_entry_modified = filetime_to_datetime(struct.unpack_from("<Q", data, fn_offset + 24)[0])
        entry.fn_accessed = filetime_to_datetime(struct.unpack_from("<Q", data, fn_offset + 32)[0])

        # Filename
        name_length = data[fn_offset + 64]
        name_namespace = data[fn_offset + 65]
        if fn_offset + 66 + name_length * 2 <= len(data):
            try:
                entry.filename = data[fn_offset + 66: fn_offset + 66 + name_length * 2].decode("utf-16-le")
            except UnicodeDecodeError:
                entry.filename = f"<entry_{entry.entry_number}>"

    def get_deleted_entries(self) -> List[MftEntry]:
        return [e for e in self._entries if not e.in_use]

    def get_entry_by_number(self, entry_num: int) -> Optional[MftEntry]:
        return self._path_map.get(entry_num)

    def get_entries_by_path(self, path_fragment: str) -> List[MftEntry]:
        path_lower = path_fragment.lower()
        return [e for e in self._entries if path_lower in e.full_path.lower()]

    def clear(self):
        self._entries.clear()
        self._path_map.clear()
