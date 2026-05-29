"""
Amcache parser.
Supports AmcacheParser CSV output and direct Amcache.hve registry hive parsing.
Tracks program execution and installation evidence.
"""

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


class AmcacheEntry:
    """Represents a single Amcache record."""

    __slots__ = [
        "full_path",
        "filename",
        "sha1",
        "file_size",
        "file_version",
        "product_name",
        "company_name",
        "pe_header_hash",
        "last_modified",
        "compiled_time",
        "created",
        "file_id",
        "program_id",
        "publisher",
        "is_pe",
        "is_oscomponent",
        "source",
    ]

    def __init__(self):
        self.full_path: str = ""
        self.filename: str = ""
        self.sha1: str = ""
        self.file_size: int = 0
        self.file_version: str = ""
        self.product_name: str = ""
        self.company_name: str = ""
        self.pe_header_hash: str = ""
        self.last_modified: Optional[datetime] = None
        self.compiled_time: Optional[datetime] = None
        self.created: Optional[datetime] = None
        self.file_id: str = ""
        self.program_id: str = ""
        self.publisher: str = ""
        self.is_pe: bool = False
        self.is_oscomponent: bool = False
        self.source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "full_path": self.full_path,
            "filename": self.filename,
            "sha1": self.sha1,
            "file_size": self.file_size,
            "file_version": self.file_version,
            "product_name": self.product_name,
            "company_name": self.company_name,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "compiled_time": self.compiled_time.isoformat() if self.compiled_time else None,
            "created": self.created.isoformat() if self.created else None,
            "is_pe": self.is_pe,
            "is_oscomponent": self.is_oscomponent,
            "source": self.source,
        }


class AmcacheParser:
    """
    Parser for Windows Amcache data.
    Supports:
    - AmcacheParser CSV output (Eric Zimmerman)
    - Generic CSV with Amcache columns
    - Direct Amcache.hve registry hive (via python-registry if available)
    """

    def __init__(self):
        self._entries: List[AmcacheEntry] = []

    @property
    def entries(self) -> List[AmcacheEntry]:
        return self._entries

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def parse(self, path: str) -> List[AmcacheEntry]:
        """Auto-detect format and parse."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")

        ext = Path(path).suffix.lower()
        if ext == ".csv":
            entries = list(self._parse_csv(path))
        elif ext in (".hve", ".bin", ""):
            entries = list(self._parse_hive(path))
        else:
            try:
                entries = list(self._parse_csv(path))
            except Exception:
                entries = list(self._parse_hive(path))

        self._entries.extend(entries)
        return entries

    def parse_live(self) -> List[AmcacheEntry]:
        """Parse Amcache from live system."""
        amcache_path = r"C:\Windows\appcompat\Programs\Amcache.hve"
        if os.path.exists(amcache_path):
            try:
                entries = list(self._parse_hive(amcache_path))
                self._entries.extend(entries)
                return entries
            except (PermissionError, OSError):
                pass
        return []

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str or ts_str.strip() == "":
            return None
        ts_str = ts_str.strip()
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str[:26].rstrip("Z"), fmt)
            except ValueError:
                continue
        return None

    def _parse_csv(self, path: str) -> Generator[AmcacheEntry, None, None]:
        """Parse AmcacheParser CSV output."""
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = AmcacheEntry()

                    entry.full_path = row.get("FullPath", row.get("Path",
                                     row.get("FilePath", row.get("full_path", ""))))
                    entry.filename = row.get("FileName", row.get("Name",
                                    row.get("filename", "")))
                    if not entry.filename and entry.full_path:
                        entry.filename = os.path.basename(entry.full_path)

                    entry.sha1 = row.get("SHA1", row.get("Sha1",
                                 row.get("FileHash", row.get("sha1", ""))))
                    # Clean SHA1 prefix
                    if entry.sha1.startswith("0000"):
                        entry.sha1 = entry.sha1.lstrip("0")

                    size_str = row.get("FileSize", row.get("Size",
                               row.get("file_size", "0")))
                    entry.file_size = int(size_str) if size_str and size_str.isdigit() else 0

                    entry.file_version = row.get("FileVersion", row.get("Version",
                                         row.get("file_version", "")))
                    entry.product_name = row.get("ProductName", row.get("Product",
                                         row.get("product_name", "")))
                    entry.company_name = row.get("CompanyName", row.get("Company",
                                         row.get("company_name", "")))

                    entry.pe_header_hash = row.get("PeHeaderHash",
                                           row.get("pe_header_hash", ""))

                    entry.last_modified = self._parse_timestamp(
                        row.get("FileKeyLastWriteTimestamp",
                        row.get("LastModified", row.get("Modified", ""))))

                    entry.compiled_time = self._parse_timestamp(
                        row.get("LinkDate", row.get("CompiledTime",
                        row.get("compiled_time", ""))))

                    entry.created = self._parse_timestamp(
                        row.get("Created", row.get("FileCreated",
                        row.get("created", ""))))

                    entry.file_id = row.get("FileId", row.get("file_id", ""))
                    entry.program_id = row.get("ProgramId", row.get("program_id", ""))
                    entry.publisher = row.get("Publisher", row.get("publisher", ""))

                    is_pe_str = row.get("IsPeFile", row.get("is_pe", ""))
                    entry.is_pe = is_pe_str.lower() in ("true", "1", "yes") if is_pe_str else False

                    is_os_str = row.get("IsOsComponent", row.get("is_oscomponent", ""))
                    entry.is_oscomponent = is_os_str.lower() in ("true", "1", "yes") if is_os_str else False

                    entry.source = path
                    yield entry
                except (ValueError, KeyError):
                    continue

    def _parse_hive(self, path: str) -> Generator[AmcacheEntry, None, None]:
        """Parse Amcache.hve registry hive directly."""
        try:
            from Registry import Registry  # type: ignore
        except ImportError:
            # Without python-registry, we can't parse the hive directly
            return

        try:
            reg = Registry.Registry(path)
        except Exception:
            return

        # Parse InventoryApplicationFile key (Win 10+)
        try:
            inv_key = reg.open("Root\\InventoryApplicationFile")
            for subkey in inv_key.subkeys():
                entry = AmcacheEntry()
                entry.source = path

                for value in subkey.values():
                    name = value.name().lower()
                    val = str(value.value()) if value.value() else ""

                    if name == "lowerCaseLongPath":
                        entry.full_path = val
                    elif name == "name":
                        entry.filename = val
                    elif name == "fileId":
                        entry.file_id = val
                        if val and len(val) > 4:
                            entry.sha1 = val.lstrip("0")
                    elif name == "size":
                        try:
                            entry.file_size = int(val)
                        except ValueError:
                            pass
                    elif name == "version":
                        entry.file_version = val
                    elif name == "productName":
                        entry.product_name = val
                    elif name == "publisher":
                        entry.publisher = val
                    elif name == "companyName":
                        entry.company_name = val
                    elif name == "linkDate":
                        entry.compiled_time = self._parse_timestamp(val)
                    elif name == "programId":
                        entry.program_id = val
                    elif name == "isPeFile":
                        entry.is_pe = val.lower() in ("1", "true")
                    elif name == "isOsComponent":
                        entry.is_oscomponent = val.lower() in ("1", "true")

                if not entry.filename and entry.full_path:
                    entry.filename = os.path.basename(entry.full_path)

                # Key last write time
                try:
                    entry.last_modified = subkey.timestamp()
                except Exception:
                    pass

                yield entry
        except Exception:
            pass

        # Parse File key (older Win 10 and Win 8.1)
        try:
            file_key = reg.open("Root\\File")
            for vol_key in file_key.subkeys():
                for entry_key in vol_key.subkeys():
                    entry = AmcacheEntry()
                    entry.source = path

                    for value in entry_key.values():
                        name = value.name()
                        val = str(value.value()) if value.value() else ""

                        if name == "15":  # Full path
                            entry.full_path = val
                        elif name == "0":  # Product name
                            entry.product_name = val
                        elif name == "1":  # Company name
                            entry.company_name = val
                        elif name == "5":  # File version
                            entry.file_version = val
                        elif name == "6":  # File size
                            try:
                                entry.file_size = int(val)
                            except ValueError:
                                pass
                        elif name == "101":  # SHA1
                            entry.sha1 = val.lstrip("0")
                        elif name == "f":  # Link date (compiled time)
                            entry.compiled_time = self._parse_timestamp(val)

                    if entry.full_path:
                        entry.filename = os.path.basename(entry.full_path)

                    try:
                        entry.last_modified = entry_key.timestamp()
                    except Exception:
                        pass

                    yield entry
        except Exception:
            pass

    def get_entries_by_path(self, path_fragment: str) -> List[AmcacheEntry]:
        path_lower = path_fragment.lower()
        return [e for e in self._entries if path_lower in (e.full_path or "").lower()]

    def get_entries_by_name(self, name: str) -> List[AmcacheEntry]:
        name_lower = name.lower()
        return [e for e in self._entries if name_lower in (e.filename or "").lower()]

    def get_entries_by_sha1(self, sha1: str) -> List[AmcacheEntry]:
        sha1_lower = sha1.lower()
        return [e for e in self._entries if sha1_lower in (e.sha1 or "").lower()]

    def get_all_paths(self) -> List[str]:
        return sorted(set(e.full_path for e in self._entries if e.full_path))

    def clear(self):
        self._entries.clear()
