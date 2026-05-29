"""
Windows Prefetch file parser.
Supports PECmd CSV output and direct .pf binary parsing.
"""

import csv
import os
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from canary.parsers.mft_parser import filetime_to_datetime


class PrefetchEntry:
    """Represents a single Prefetch file record."""

    __slots__ = [
        "executable_name",
        "prefetch_hash",
        "source_file",
        "run_count",
        "last_run_times",
        "created",
        "modified",
        "file_size",
        "volume_path",
        "volume_created",
        "volume_serial",
        "directories_referenced",
        "files_referenced",
    ]

    def __init__(self):
        self.executable_name: str = ""
        self.prefetch_hash: str = ""
        self.source_file: str = ""
        self.run_count: int = 0
        self.last_run_times: List[datetime] = []
        self.created: Optional[datetime] = None
        self.modified: Optional[datetime] = None
        self.file_size: int = 0
        self.volume_path: str = ""
        self.volume_created: Optional[datetime] = None
        self.volume_serial: str = ""
        self.directories_referenced: List[str] = []
        self.files_referenced: List[str] = []

    @property
    def latest_run(self) -> Optional[datetime]:
        return self.last_run_times[0] if self.last_run_times else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executable_name": self.executable_name,
            "prefetch_hash": self.prefetch_hash,
            "source_file": self.source_file,
            "run_count": self.run_count,
            "last_run_times": [t.isoformat() for t in self.last_run_times],
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "file_size": self.file_size,
        }


# Prefetch file signatures
PF_SIGNATURE_WIN10 = 0x1E  # MAM compressed
PF_SIGNATURE_V30 = 30
PF_SIGNATURE_V26 = 26
PF_SIGNATURE_V23 = 23
PF_SIGNATURE_V17 = 17

PREFETCH_MAGIC = b"\x53\x43\x43\x41"  # SCCA


class PrefetchParser:
    """
    Parser for Windows Prefetch data.
    Supports:
    - PECmd CSV output (primary recommended format)
    - Direct .pf file parsing (Win XP through Win 11)
    - Directory of .pf files
    """

    def __init__(self):
        self._entries: List[PrefetchEntry] = []

    @property
    def entries(self) -> List[PrefetchEntry]:
        return self._entries

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def parse(self, path: str) -> List[PrefetchEntry]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        if os.path.isdir(path):
            return self._parse_directory(path)

        ext = Path(path).suffix.lower()
        if ext == ".csv":
            entries = list(self._parse_pecmd_csv(path))
        elif ext == ".pf":
            entry = self._parse_pf_file(path)
            entries = [entry] if entry else []
        else:
            try:
                entries = list(self._parse_pecmd_csv(path))
            except Exception:
                entries = []

        self._entries.extend(entries)
        return entries

    def _parse_directory(self, dir_path: str) -> List[PrefetchEntry]:
        """Parse all .pf files in a directory (typically C:\\Windows\\Prefetch)."""
        entries = []
        for fname in os.listdir(dir_path):
            fpath = os.path.join(dir_path, fname)
            if fname.lower().endswith(".pf") and os.path.isfile(fpath):
                try:
                    entry = self._parse_pf_file(fpath)
                    if entry:
                        entries.append(entry)
                except Exception:
                    continue
            elif fname.lower().endswith(".csv"):
                try:
                    csv_entries = list(self._parse_pecmd_csv(fpath))
                    entries.extend(csv_entries)
                except Exception:
                    continue

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

    def _parse_pecmd_csv(self, path: str) -> Generator[PrefetchEntry, None, None]:
        """Parse PECmd CSV output."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = PrefetchEntry()

                    entry.executable_name = row.get("ExecutableName", row.get("SourceFilename", ""))
                    entry.prefetch_hash = row.get("Hash", row.get("PrefetchHash", ""))
                    entry.source_file = row.get("SourceFile", row.get("SourceFilename", ""))

                    run_count = row.get("RunCount", row.get("run_count", "0"))
                    entry.run_count = int(run_count) if run_count else 0

                    # Parse last run times (PECmd outputs up to 8)
                    for i in range(8):
                        col_name = f"LastRun{i}" if i > 0 else "LastRun"
                        alt_name = f"PreviousRun{i}" if i > 0 else "LastRun"
                        ts_str = row.get(col_name, row.get(alt_name, ""))
                        ts = self._parse_timestamp(ts_str)
                        if ts:
                            entry.last_run_times.append(ts)

                    # Also try comma-separated RunTimes
                    run_times_str = row.get("RunTimes", "")
                    if run_times_str and not entry.last_run_times:
                        for ts_str in run_times_str.split(","):
                            ts = self._parse_timestamp(ts_str.strip())
                            if ts:
                                entry.last_run_times.append(ts)

                    entry.created = self._parse_timestamp(row.get("SourceCreated", row.get("Created", "")))
                    entry.modified = self._parse_timestamp(row.get("SourceModified", row.get("Modified", "")))

                    size_str = row.get("Size", row.get("FileSize", "0"))
                    entry.file_size = int(size_str) if size_str else 0

                    entry.volume_path = row.get("Volume0Name", row.get("VolumePath", ""))
                    entry.volume_serial = row.get("Volume0Serial", row.get("VolumeSerial", ""))

                    # Parse referenced directories and files if available
                    dirs_str = row.get("Directories", "")
                    if dirs_str:
                        entry.directories_referenced = [d.strip() for d in dirs_str.split(",") if d.strip()]

                    files_str = row.get("FilesLoaded", "")
                    if files_str:
                        entry.files_referenced = [f.strip() for f in files_str.split(",") if f.strip()]

                    yield entry
                except (ValueError, KeyError):
                    continue

    def _parse_pf_file(self, path: str) -> Optional[PrefetchEntry]:
        """Parse a single .pf (Prefetch) binary file."""
        try:
            with open(path, "rb") as f:
                data = f.read()
        except (IOError, OSError):
            return None

        if len(data) < 84:
            return None

        entry = PrefetchEntry()
        entry.source_file = path

        # Check if MAM compressed (Win 10+)
        if data[:4] == b"\x4d\x41\x4d\x04":
            data = self._decompress_mam(data)
            if not data:
                return None

        # Verify SCCA signature at offset 4
        if len(data) < 84 or data[4:8] != PREFETCH_MAGIC:
            # Try without compression check
            if data[:4] == PREFETCH_MAGIC:
                pass  # Some formats have SCCA at offset 0
            else:
                return None

        # Determine version
        version = struct.unpack_from("<I", data, 0)[0]

        # Extract executable name (60 bytes at offset 16, UTF-16LE)
        try:
            name_bytes = data[16:76]
            entry.executable_name = name_bytes.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            entry.executable_name = os.path.basename(path).replace(".pf", "")

        # Extract hash from filename
        fname = os.path.basename(path).upper()
        if "-" in fname:
            hash_part = fname.split("-")[-1].replace(".PF", "")
            entry.prefetch_hash = hash_part

        # Version-specific parsing
        if version == PF_SIGNATURE_V30 or version == PF_SIGNATURE_V26:
            entry = self._parse_v30(data, entry)
        elif version == PF_SIGNATURE_V23:
            entry = self._parse_v23(data, entry)
        elif version == PF_SIGNATURE_V17:
            entry = self._parse_v17(data, entry)

        # Get file timestamps from OS
        try:
            stat = os.stat(path)
            entry.created = datetime.fromtimestamp(stat.st_ctime)
            entry.modified = datetime.fromtimestamp(stat.st_mtime)
            entry.file_size = stat.st_size
        except OSError:
            pass

        return entry

    def _decompress_mam(self, data: bytes) -> Optional[bytes]:
        """Decompress MAM-compressed Prefetch file (Win 10+)."""
        if len(data) < 8:
            return None

        # MAM header: magic (4 bytes) + uncompressed size (4 bytes)
        uncompressed_size = struct.unpack_from("<I", data, 4)[0]
        compressed_data = data[8:]

        # Try xpress huffman decompression
        try:
            import lznt1  # type: ignore
            return lznt1.decompress(compressed_data, uncompressed_size)
        except ImportError:
            pass

        # Try using Windows native decompression
        try:
            import ctypes
            ntdll = ctypes.windll.ntdll
            buf = ctypes.create_string_buffer(uncompressed_size)
            final_size = ctypes.c_ulong(0)
            # RtlDecompressBufferEx with XPRESS_HUFF (4)
            status = ntdll.RtlDecompressBufferEx(
                4,  # COMPRESSION_FORMAT_XPRESS_HUFF
                buf,
                uncompressed_size,
                compressed_data,
                len(compressed_data),
                ctypes.byref(final_size),
                None,
            )
            if status == 0:
                return buf.raw[:final_size.value]
        except (OSError, AttributeError):
            pass

        return None

    def _parse_v30(self, data: bytes, entry: PrefetchEntry) -> PrefetchEntry:
        """Parse Prefetch v30 (Win 10) structure."""
        if len(data) < 108:
            return entry

        try:
            # Run count at offset 208
            if len(data) > 212:
                entry.run_count = struct.unpack_from("<I", data, 208)[0]

            # Last run times (up to 8) starting at offset 128
            if len(data) > 192:
                for i in range(8):
                    offset = 128 + (i * 8)
                    if offset + 8 <= len(data):
                        ft = struct.unpack_from("<Q", data, offset)[0]
                        ts = filetime_to_datetime(ft)
                        if ts:
                            entry.last_run_times.append(ts)
        except struct.error:
            pass

        return entry

    def _parse_v26(self, data: bytes, entry: PrefetchEntry) -> PrefetchEntry:
        """Parse Prefetch v26 (Win 8.1) structure."""
        return self._parse_v30(data, entry)  # Similar structure

    def _parse_v23(self, data: bytes, entry: PrefetchEntry) -> PrefetchEntry:
        """Parse Prefetch v23 (Win Vista/7) structure."""
        if len(data) < 156:
            return entry

        try:
            if len(data) > 152:
                entry.run_count = struct.unpack_from("<I", data, 152)[0]

            # Last run time at offset 128
            if len(data) > 136:
                ft = struct.unpack_from("<Q", data, 128)[0]
                ts = filetime_to_datetime(ft)
                if ts:
                    entry.last_run_times.append(ts)
        except struct.error:
            pass

        return entry

    def _parse_v17(self, data: bytes, entry: PrefetchEntry) -> PrefetchEntry:
        """Parse Prefetch v17 (Win XP) structure."""
        if len(data) < 156:
            return entry

        try:
            if len(data) > 144:
                entry.run_count = struct.unpack_from("<I", data, 144)[0]

            if len(data) > 128:
                ft = struct.unpack_from("<Q", data, 120)[0]
                ts = filetime_to_datetime(ft)
                if ts:
                    entry.last_run_times.append(ts)
        except struct.error:
            pass

        return entry

    def get_entry_by_name(self, name: str) -> List[PrefetchEntry]:
        name_lower = name.lower()
        return [e for e in self._entries if name_lower in e.executable_name.lower()]

    def get_executable_names(self) -> List[str]:
        return sorted(set(e.executable_name for e in self._entries if e.executable_name))

    def clear(self):
        self._entries.clear()
