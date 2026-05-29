<div align="center">

# 🐤 Canary

### Anti-Forensics Detector

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)]()

**Systematically scans forensic artifacts for evidence of tampering, log manipulation, timestomping, and anti-forensic tool usage.**

*Answers the critical question every forensic examiner faces: "Has this evidence been tampered with?"*

[Getting Started](#quick-start) · [Supported Inputs](#supported-input-formats) · [Architecture](#architecture)

</div>

---

## What It Detects

| Check | What It Finds |
|-------|--------------|
| **Log Gap Detection** | Missing Event Log record IDs, log clearing events (1102/104), suspicious time gaps |
| **Timestomping** | $SI vs $FN timestamp mismatches, impossible timestamps, batch timestomping, zero-precision timestamps |
| **USN Journal Tampering** | Truncated journals, sequence gaps, bulk deletions, forensic artifact deletion |
| **Prefetch Anomalies** | Anti-forensic tool execution, missing expected prefetch, selective deletion |
| **Sysmon/Audit Gaps** | Service stops, config changes, monitoring gaps, Defender tampering |
| **Shellbag Inconsistencies** | Ghost directories (deleted paths still in shellbags), staging directories, external devices |
| **Anti-Forensic Tools** | 100+ known tools detected across Prefetch/Shimcache/Amcache (SDelete, Mimikatz, CCleaner, etc.) |
| **Registry Anomalies** | Disabled security features, anti-forensic tool artifacts, suspicious persistence |

## Quick Start

### One-Click Run (Windows)
```
run.bat --live
```

### One-Click Run (Linux/Mac)
```bash
chmod +x run.sh
./run.sh --help
```

### Import Mode (Pre-Parsed Artifacts)
```bash
python -m canary \
  --mft-csv MFT_output.csv \
  --usn-csv J_output.csv \
  --evtx-path ./exported_logs/ \
  --prefetch-csv Prefetch.csv \
  --shimcache-csv AppCompatCache.csv \
  --amcache-csv Amcache.csv \
  --shellbags-csv Shellbags.csv \
  --format both \
  --output-dir ./report
```

### Live Mode (Windows, requires Admin)
```bash
python -m canary --live --format html --output-dir ./report
```

### With Incident Time Window
```bash
python -m canary --mft-csv MFT.csv --evtx-path ./logs/ \
  --incident-start "2024-03-15 08:00" \
  --incident-end "2024-03-15 18:00"
```

## Supported Input Formats

| Artifact | Tool to Export | Format |
|----------|---------------|--------|
| MFT | [MFTECmd](https://github.com/EricZimmerman/MFTECmd) | CSV |
| USN Journal | MFTECmd (`$J` parsing) | CSV |
| Event Logs | [EvtxECmd](https://github.com/EricZimmerman/evtx) / Event Viewer export | EVTX, JSON, CSV, XML |
| Prefetch | [PECmd](https://github.com/EricZimmerman/PECmd) / direct `.pf` files | CSV, .pf directory |
| Shimcache | [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) | CSV |
| Amcache | [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser) | CSV, .hve |
| Shellbags | [SBECmd](https://github.com/EricZimmerman/SBECmd) | CSV |
| Registry | [RECmd](https://github.com/EricZimmerman/RECmd) | CSV |

## Output

- **HTML Report**: Beautiful dark-themed interactive report with severity scoring, MITRE ATT&CK mapping, and expandable findings
- **JSON Report**: Machine-readable structured output for integration with other tools
- **Tampering Score**: 0-100 score indicating overall evidence of anti-forensic activity
- **MITRE ATT&CK Mapping**: Each finding mapped to relevant ATT&CK techniques

## Requirements

- Python 3.9+
- No external services, no cloud, no AI, no paid dependencies
- Optional: `python-evtx` for direct `.evtx` parsing
- Optional: `python-registry` for direct registry hive parsing

## Architecture

```
canary/
├── checks/          # Detection modules (8 checks)
│   ├── log_gaps.py         # Event log gap analysis
│   ├── timestomping.py     # $SI/$FN timestamp comparison
│   ├── usn_journal.py      # USN Journal integrity
│   ├── prefetch.py         # Prefetch anomaly detection
│   ├── sysmon_gaps.py      # Sysmon/audit monitoring gaps
│   ├── shellbags.py        # Shellbag inconsistencies
│   ├── antiforensic_tools.py  # Known tool detection (100+)
│   └── registry.py         # Registry anomaly detection
├── parsers/         # Artifact parsers
│   ├── evtx_parser.py      # EVTX/JSON/CSV/XML event logs
│   ├── mft_parser.py       # MFT CSV and raw binary
│   ├── usn_parser.py       # USN Journal CSV and raw binary
│   ├── prefetch_parser.py  # Prefetch CSV and .pf binary
│   ├── shimcache_parser.py # Shimcache CSV and registry binary
│   └── amcache_parser.py   # Amcache CSV and .hve hive
├── models.py        # Data models, severity/confidence enums
├── engine.py        # Scan orchestration engine
├── report.py        # HTML/JSON report generator
└── cli.py           # Command-line interface
```

## License

MIT — see [LICENSE](LICENSE) for details.
