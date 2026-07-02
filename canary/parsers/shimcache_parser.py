"""
Shimcache (AppCompatCache) parser.
Supports AppCompatCacheParser CSV output and registry binary extraction.
Tracks program execution evidence for cross-referencing with other artifacts.
"""

import csv
import os
import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from canary.parsers.mft_parser import filetime_to_datetime


class ShimcacheEntry:
    """Represents a single Shimcache entry."""

    __slots__ = [
        "order",
        "path",
        "last_modified",
        "executed",
        "duplicate",
        "source",
    ]

    def __init__(self):
        self.order: int = 0
        self.path: str = ""
        self.last_modified: Optional[datetime] = None
        self.executed: Optional[bool] = None
        self.duplicate: bool = False
        self.source: str = ""

    @property
    def filename(self) -> str:
        return os.path.basename(self.path) if self.path else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order": self.order,
            "path": self.path,
            "filename": self.filename,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "executed": self.executed,
            "duplicate": self.duplicate,
            "source": self.source,
        }


# Shimcache header signatures for different Windows versions
CACHE_MAGIC_NT61 = 0xBADC0FEE  # Win 7 / Server 2008 R2
CACHE_MAGIC_NT62 = 0xBADC0FFE  # Win 8 / Server 2012
CACHE_MAGIC_NT52 = 0xDEADBEEF  # Win XP


class ShimcacheParser:
    """
    Parser for Windows Shimcache (AppCompatCache) data.
    Supports:
    - AppCompatCacheParser CSV output (Eric Zimmerman)
    - Direct registry extraction on live systems
    - Registry hive binary extraction
    """

    def __init__(self):
        self._entries: List[ShimcacheEntry] = []

    @property
    def entries(self) -> List[ShimcacheEntry]:
        return self._entries

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def parse(self, path: str) -> List[ShimcacheEntry]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        ext = Path(path).suffix.lower()
        if ext == ".csv":
            entries = list(self._parse_csv(path))
        elif ext in (".bin", ".reg", ""):
            entries = list(self._parse_binary(path))
        else:
            try:
                entries = list(self._parse_csv(path))
            except Exception:
                entries = list(self._parse_binary(path))

        self._entries.extend(entries)
        return entries

    def parse_live(self) -> List[ShimcacheEntry]:
        """Parse Shimcache directly from live system registry."""
        entries = []
        try:
            import winreg
        except ImportError:
            return entries

        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                value_data, value_type = winreg.QueryValueEx(key, "AppCompatCache")
                if isinstance(value_data, bytes):
                    entries = list(self._parse_appcompat_data(value_data))
        except OSError:
            # Try ControlSet001
            try:
                key_path = r"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    value_data, value_type = winreg.QueryValueEx(key, "AppCompatCache")
                    if isinstance(value_data, bytes):
                        entries = list(self._parse_appcompat_data(value_data))
            except OSError:
                pass

        for e in entries:
            e.source = "live_registry"
        self._entries.extend(entries)
        return entries

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

    def _parse_csv(self, path: str) -> Generator[ShimcacheEntry, None, None]:
        """Parse AppCompatCacheParser CSV output."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            order = 0
            for row in reader:
                try:
                    entry = ShimcacheEntry()
                    order += 1

                    order_str = row.get("ControlSet", row.get("Order", row.get("#", str(order))))
                    entry.order = int(order_str) if order_str and order_str.isdigit() else order

                    entry.path = row.get("Path", row.get("FileName", row.get("path", "")))

                    ts_str = row.get("LastModifiedTimeUTC", row.get("LastModified",
                             row.get("Modified", row.get("Timestamp", ""))))
                    entry.last_modified = self._parse_timestamp(ts_str)

                    exec_str = row.get("Executed", row.get("executed", ""))
                    if exec_str:
                        exec_lower = exec_str.lower().strip()
                        if exec_lower in ("true", "yes", "1"):
                            entry.executed = True
                        elif exec_lower in ("false", "no", "0"):
                            entry.executed = False

                    dup_str = row.get("Duplicate", row.get("duplicate", "false"))
                    entry.duplicate = dup_str.lower() in ("true", "yes", "1") if dup_str else False

                    entry.source = path
                    yield entry
                except (ValueError, KeyError):
                    continue

    def _parse_binary(self, path: str) -> Generator[ShimcacheEntry, None, None]:
        """Parse binary registry export containing AppCompatCache data."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            yield from self._parse_appcompat_data(data)
        except (IOError, OSError):
            return

    def _parse_appcompat_data(self, data: bytes) -> Generator[ShimcacheEntry, None, None]:
        """Parse raw AppCompatCache binary data."""
        if len(data) < 4:
            return

        # Detect format version
        magic = struct.unpack_from("<I", data, 0)[0]

        if magic == CACHE_MAGIC_NT61:
            yield from self._parse_nt61(data)
        elif magic == CACHE_MAGIC_NT62:
            yield from self._parse_nt62(data)
        elif magic == CACHE_MAGIC_NT52:
            yield from self._parse_nt52(data)
        else:
            # Win 10 format (no magic, starts with 0x30/0x34)
            yield from self._parse_win10(data)

    def _parse_win10(self, data: bytes) -> Generator[ShimcacheEntry, None, None]:
        """Parse Windows 10/11 AppCompatCache format."""
        if len(data) < 48:
            return

        # Win10 format: header (48 bytes) then entries
        # Each entry: signature (4), unknown (4), data_size (4), path_size (2), ...
        sig_offset = 48
        order = 0

        while sig_offset < len(data) - 12:
            # Look for entry signature "10ts"
            sig = data[sig_offset: sig_offset + 4]
            if sig != b"10ts":
                sig_offset += 4
                if sig_offset > len(data) - 12:
                    break
                continue

            try:
                order += 1
                entry = ShimcacheEntry()
                entry.order = order

                # Unknown (4 bytes)
                # CRC (4 bytes at sig+4)
                # Data size (4 bytes at sig+8)
                data_size = struct.unpack_from("<I", data, sig_offset + 8)[0]

                # Path size (2 bytes at sig+12)
                path_size = struct.unpack_from("<H", data, sig_offset + 12)[0]

                # Path starts at sig+14
                path_offset = sig_offset + 14
                if path_offset + path_size <= len(data):
                    try:
                        entry.path = data[path_offset: path_offset + path_size].decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        entry.path = "<decode_error>"

                # Timestamp after path
                ts_offset = path_offset + path_size
                if ts_offset + 8 <= len(data):
                    ft = struct.unpack_from("<Q", data, ts_offset)[0]
                    entry.last_modified = filetime_to_datetime(ft)

                entry.source = "binary_win10"
                yield entry

                sig_offset += 12 + data_size
            except (struct.error, ValueError):
                sig_offset += 4

    def _parse_nt61(self, data: bytes) -> Generator[ShimcacheEntry, None, None]:
        """Parse Windows 7/Server 2008 R2 format."""
        if len(data) < 128:
            return

        num_entries = struct.unpack_from("<I", data, 4)[0]
        offset = 128
        order = 0

        for _ in range(min(num_entries, 1024)):
            if offset + 48 > len(data):
                break

            order += 1
            entry = ShimcacheEntry()
            entry.order = order

            try:
                path_size = struct.unpack_from("<H", data, offset)[0]
                max_path_size = struct.unpack_from("<H", data, offset + 2)[0]
                path_ptr = struct.unpack_from("<I", data, offset + 4)[0]

                ft_low = struct.unpack_from("<I", data, offset + 8)[0]
                ft_high = struct.unpack_from("<I", data, offset + 12)[0]
                filetime = (ft_high << 32) | ft_low
                entry.last_modified = filetime_to_datetime(filetime)

                flags = struct.unpack_from("<I", data, offset + 16)[0]
                entry.executed = bool(flags & 0x02)

                data_size = struct.unpack_from("<I", data, offset + 20)[0]

                # Extract path
                if path_ptr > 0 and path_ptr + path_size <= len(data):
                    try:
                        entry.path = data[path_ptr: path_ptr + path_size].decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        entry.path = "<decode_error>"

                entry.source = "binary_nt61"
                yield entry

                offset += 32 + data_size
            except (struct.error, ValueError):
                break

    def _parse_nt62(self, data: bytes) -> Generator[ShimcacheEntry, None, None]:
        """Parse Windows 8/Server 2012 format."""
        if len(data) < 128:
            return

        offset = 128
        order = 0

        while offset < len(data) - 12:
            sig = data[offset: offset + 4]
            if sig != b"10ts":
                break

            order += 1
            entry = ShimcacheEntry()
            entry.order = order

            try:
                entry_len = struct.unpack_from("<I", data, offset + 8)[0]
                path_size = struct.unpack_from("<H", data, offset + 12)[0]

                path_start = offset + 14
                if path_start + path_size <= len(data):
                    try:
                        entry.path = data[path_start: path_start + path_size].decode("utf-16-le").rstrip("\x00")
                    except UnicodeDecodeError:
                        entry.path = "<decode_error>"

                ts_offset = path_start + path_size
                if ts_offset + 8 <= len(data):
                    ft = struct.unpack_from("<Q", data, ts_offset)[0]
                    entry.last_modified = filetime_to_datetime(ft)

                entry.source = "binary_nt62"
                yield entry

                offset += 12 + entry_len
            except (struct.error, ValueError):
                break

    def _parse_nt52(self, data: bytes) -> Generator[ShimcacheEntry, None, None]:
        """Parse Windows XP format."""
        if len(data) < 400:
            return

        num_entries = struct.unpack_from("<I", data, 4)[0]
        offset = 400
        order = 0

        for _ in range(min(num_entries, 96)):
            if offset + 552 > len(data):
                break

            order += 1
            entry = ShimcacheEntry()
            entry.order = order

            try:
                path_bytes = data[offset: offset + 528]
                try:
                    entry.path = path_bytes.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    entry.path = "<decode_error>"

                ft = struct.unpack_from("<Q", data, offset + 528)[0]
                entry.last_modified = filetime_to_datetime(ft)

                entry.file_size = struct.unpack_from("<Q", data, offset + 536)[0]

                entry.source = "binary_nt52"
                yield entry

                offset += 552
            except (struct.error, ValueError):
                break

    def get_entries_by_path(self, path_fragment: str) -> List[ShimcacheEntry]:
        path_lower = path_fragment.lower()
        return [e for e in self._entries if path_lower in e.path.lower()]

    def get_executed_entries(self) -> List[ShimcacheEntry]:
        return [e for e in self._entries if e.executed is True]

    def get_paths(self) -> List[str]:
        return sorted(set(e.path for e in self._entries if e.path))

    def clear(self):
        self._entries.clear()
