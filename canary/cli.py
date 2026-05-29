"""
Canary CLI - Command-line interface for the Anti-Forensics Detector.
"""

import os
import sys
import argparse
from datetime import datetime
from typing import List, Optional

from canary.models import ScanConfig
from canary.engine import CanaryEngine
from canary.report import ReportGenerator


def parse_datetime(s: str) -> Optional[datetime]:
    """Parse a datetime string from CLI argument."""
    if not s:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    print(f"Error: Cannot parse datetime '{s}'. Use format: YYYY-MM-DD HH:MM:SS")
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="canary",
        description=(
            "Canary - Anti-Forensics Detector\n"
            "Detects evidence tampering, log manipulation, timestomping, "
            "and anti-forensic tool usage."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan live system (requires admin)
  python -m canary --live

  # Scan with pre-parsed artifacts
  python -m canary --mft-csv MFT.csv --usn-csv J.csv --evtx-path ./logs/

  # Full analysis with all artifact sources
  python -m canary \\
    --mft-csv MFT.csv \\
    --usn-csv J.csv \\
    --evtx-path ./evtx_exports/ \\
    --prefetch-csv Prefetch.csv \\
    --shimcache-csv AppCompatCache.csv \\
    --amcache-csv Amcache.csv \\
    --shellbags-csv Shellbags.csv \\
    --output-dir ./report \\
    --format both

  # Scan with incident time window
  python -m canary --mft-csv MFT.csv --evtx-path ./logs/ \\
    --incident-start "2024-03-15 08:00" \\
    --incident-end "2024-03-15 18:00"
""",
    )

    # Mode
    mode_group = parser.add_argument_group("Scan Mode")
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Scan the live system (requires admin privileges)",
    )

    # Data sources
    data_group = parser.add_argument_group("Data Sources (Import Mode)")
    data_group.add_argument(
        "--evtx-path",
        action="append",
        default=[],
        dest="evtx_paths",
        help="Path to EVTX file(s) or directory containing EVTX/JSON/CSV logs (can specify multiple)",
    )
    data_group.add_argument(
        "--mft-csv",
        dest="mft_csv",
        help="Path to MFTECmd CSV output ($MFT parsed)",
    )
    data_group.add_argument(
        "--usn-csv",
        dest="usn_csv",
        help="Path to MFTECmd $J CSV output (USN Journal parsed)",
    )
    data_group.add_argument(
        "--prefetch-csv",
        dest="prefetch_csv",
        help="Path to PECmd CSV output or Prefetch directory",
    )
    data_group.add_argument(
        "--shimcache-csv",
        dest="shimcache_csv",
        help="Path to AppCompatCacheParser CSV output",
    )
    data_group.add_argument(
        "--amcache-csv",
        dest="amcache_csv",
        help="Path to AmcacheParser CSV output",
    )
    data_group.add_argument(
        "--shellbags-csv",
        dest="shellbags_csv",
        help="Path to SBECmd CSV output (Shellbags)",
    )
    data_group.add_argument(
        "--sysmon-log",
        dest="sysmon_log",
        help="Path to Sysmon log file (EVTX or JSON)",
    )
    data_group.add_argument(
        "--registry",
        action="append",
        default=[],
        dest="registry_paths",
        help="Path to registry export (RECmd CSV) (can specify multiple)",
    )
    data_group.add_argument(
        "--filesystem-root",
        dest="filesystem_root",
        help="Root path of the filesystem being analyzed (for ghost directory checks)",
    )

    # Incident window
    incident_group = parser.add_argument_group("Incident Window")
    incident_group.add_argument(
        "--incident-start",
        dest="incident_start",
        help="Incident start time (YYYY-MM-DD HH:MM:SS)",
    )
    incident_group.add_argument(
        "--incident-end",
        dest="incident_end",
        help="Incident end time (YYYY-MM-DD HH:MM:SS)",
    )

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--output-dir", "-o",
        default=".",
        dest="output_dir",
        help="Directory to save reports (default: current directory)",
    )
    output_group.add_argument(
        "--format", "-f",
        choices=["html", "json", "both"],
        default="html",
        help="Output format (default: html)",
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser


def main(args: Optional[List[str]] = None):
    """Main entry point for Canary CLI."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    # Build configuration
    config = ScanConfig(
        mode="live" if parsed.live else "import",
        evtx_paths=parsed.evtx_paths,
        mft_csv_path=parsed.mft_csv,
        usn_csv_path=parsed.usn_csv,
        prefetch_csv_path=parsed.prefetch_csv,
        shimcache_csv_path=parsed.shimcache_csv,
        amcache_csv_path=parsed.amcache_csv,
        shellbags_csv_path=parsed.shellbags_csv,
        sysmon_log_path=parsed.sysmon_log,
        registry_hive_paths=parsed.registry_paths,
        filesystem_root=parsed.filesystem_root,
        output_dir=parsed.output_dir,
        output_format=parsed.format,
        verbose=parsed.verbose,
        incident_start=parse_datetime(parsed.incident_start) if parsed.incident_start else None,
        incident_end=parse_datetime(parsed.incident_end) if parsed.incident_end else None,
    )

    # Validate we have something to scan
    if config.mode == "import":
        has_data = any([
            config.evtx_paths,
            config.mft_csv_path,
            config.usn_csv_path,
            config.prefetch_csv_path,
            config.shimcache_csv_path,
            config.amcache_csv_path,
            config.shellbags_csv_path,
            config.sysmon_log_path,
            config.registry_hive_paths,
        ])
        if not has_data:
            print("Error: No data sources specified. Use --live for live scanning")
            print("       or provide artifact paths. Use --help for options.")
            sys.exit(1)

    # Run engine
    engine = CanaryEngine(config)
    result = engine.run()

    # Generate report
    report_gen = ReportGenerator(result, config.output_dir)
    output_path = report_gen.generate(config.output_format)

    print(f"\n  📄 Report saved to: {output_path}")

    # Return exit code based on findings
    if result.tampering_score >= 70:
        return 2  # Critical
    elif result.tampering_score >= 20:
        return 1  # Warnings
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
