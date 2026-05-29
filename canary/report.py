"""
Canary Report Generator.
Produces beautiful HTML and JSON reports from scan results.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from canary.models import (
    Finding,
    ScanResult,
    Severity,
    Confidence,
    CheckCategory,
    MITRE_MAPPING,
)


class ReportGenerator:
    """Generates HTML and JSON reports from Canary scan results."""

    def __init__(self, result: ScanResult, output_dir: str = "."):
        self.result = result
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, fmt: str = "html") -> str:
        """Generate report in specified format. Returns output file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            return self._generate_json(timestamp)
        elif fmt == "both":
            json_path = self._generate_json(timestamp)
            html_path = self._generate_html(timestamp)
            print(f"  Reports saved to:")
            print(f"    HTML: {html_path}")
            print(f"    JSON: {json_path}")
            return html_path
        else:
            return self._generate_html(timestamp)

    def _generate_json(self, timestamp: str) -> str:
        """Generate JSON report."""
        path = os.path.join(self.output_dir, f"canary_report_{timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.result.to_dict(), f, indent=2, default=str)
        return path

    def _generate_html(self, timestamp: str) -> str:
        """Generate HTML report."""
        path = os.path.join(self.output_dir, f"canary_report_{timestamp}.html")

        html = self._build_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _severity_color(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#ca8a04",
            Severity.LOW: "#2563eb",
            Severity.INFO: "#6b7280",
        }.get(severity, "#6b7280")

    def _severity_bg(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "#fef2f2",
            Severity.HIGH: "#fff7ed",
            Severity.MEDIUM: "#fefce8",
            Severity.LOW: "#eff6ff",
            Severity.INFO: "#f9fafb",
        }.get(severity, "#f9fafb")

    def _confidence_badge(self, confidence: Confidence) -> str:
        colors = {
            Confidence.CONFIRMED: ("#065f46", "#d1fae5"),
            Confidence.HIGH: ("#1e40af", "#dbeafe"),
            Confidence.MEDIUM: ("#92400e", "#fef3c7"),
            Confidence.LOW: ("#6b7280", "#f3f4f6"),
            Confidence.SPECULATIVE: ("#9ca3af", "#f9fafb"),
        }
        fg, bg = colors.get(confidence, ("#6b7280", "#f3f4f6"))
        return (
            f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:4px;font-size:12px;font-weight:600;">'
            f'{confidence.value.upper()}</span>'
        )

    def _score_color(self, score: int) -> str:
        if score >= 70:
            return "#dc2626"
        elif score >= 40:
            return "#ea580c"
        elif score >= 20:
            return "#ca8a04"
        elif score > 0:
            return "#2563eb"
        return "#16a34a"

    def _build_html(self) -> str:
        result = self.result
        score = result.tampering_score
        summary = result.summary

        findings_html = self._build_findings_html()
        mitre_html = self._build_mitre_html()
        category_chart_data = self._build_category_data()

        duration = ""
        if result.scan_start and result.scan_end:
            dur = (result.scan_end - result.scan_start).total_seconds()
            duration = f"{dur:.1f}s"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Canary Anti-Forensics Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

/* Header */
.header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
           border: 1px solid #334155; border-radius: 12px; padding: 32px;
           margin-bottom: 24px; }}
.header h1 {{ font-size: 28px; color: #f8fafc; margin-bottom: 4px; }}
.header .subtitle {{ color: #94a3b8; font-size: 14px; }}
.header .meta {{ display: flex; gap: 24px; margin-top: 16px; color: #94a3b8; font-size: 13px; }}

/* Score Card */
.score-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
              padding: 32px; margin-bottom: 24px; text-align: center; }}
.score-value {{ font-size: 72px; font-weight: 800; color: {self._score_color(score)};
               line-height: 1; }}
.score-label {{ font-size: 14px; color: #94a3b8; margin-top: 8px; text-transform: uppercase;
               letter-spacing: 2px; }}
.score-grade {{ font-size: 16px; margin-top: 12px; padding: 8px 16px; border-radius: 8px;
               display: inline-block; background: {self._score_color(score)}22;
               color: {self._score_color(score)}; font-weight: 600; }}

/* Summary Grid */
.summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px;
                margin-bottom: 24px; }}
.summary-item {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                padding: 16px; text-align: center; }}
.summary-count {{ font-size: 32px; font-weight: 700; }}
.summary-label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase;
                 letter-spacing: 1px; margin-top: 4px; }}

/* Findings */
.findings {{ margin-bottom: 24px; }}
.findings h2 {{ font-size: 20px; color: #f8fafc; margin-bottom: 16px;
               padding-bottom: 8px; border-bottom: 1px solid #334155; }}
.finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
           margin-bottom: 12px; overflow: hidden; }}
.finding-header {{ padding: 16px 20px; cursor: pointer; display: flex;
                  align-items: center; gap: 12px; }}
.finding-header:hover {{ background: #334155; }}
.finding-severity {{ width: 4px; height: 40px; border-radius: 2px; flex-shrink: 0; }}
.finding-title {{ flex: 1; }}
.finding-title h3 {{ font-size: 15px; color: #f8fafc; }}
.finding-title .meta {{ font-size: 12px; color: #94a3b8; margin-top: 4px; display: flex;
                       gap: 8px; align-items: center; }}
.finding-body {{ padding: 0 20px 20px 36px; display: none; }}
.finding-body.open {{ display: block; }}
.finding-desc {{ color: #cbd5e1; margin-bottom: 16px; font-size: 14px; }}
.evidence-box {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
                padding: 12px 16px; font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px; color: #94a3b8; white-space: pre-wrap;
                margin-bottom: 12px; max-height: 300px; overflow-y: auto; }}
.recommendation {{ background: #172554; border: 1px solid #1e3a5f; border-radius: 6px;
                  padding: 12px 16px; font-size: 13px; color: #93c5fd; }}
.recommendation strong {{ color: #60a5fa; }}
.mitre-tag {{ background: #7c3aed22; color: #a78bfa; padding: 2px 8px;
             border-radius: 4px; font-size: 11px; font-weight: 600; }}

/* MITRE Section */
.mitre-section {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
                 padding: 24px; margin-bottom: 24px; }}
.mitre-section h2 {{ font-size: 20px; color: #f8fafc; margin-bottom: 16px; }}
.mitre-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
              gap: 12px; }}
.mitre-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; }}
.mitre-card .technique {{ color: #a78bfa; font-weight: 600; font-size: 14px; }}
.mitre-card .tactic {{ color: #94a3b8; font-size: 12px; }}
.mitre-card .count {{ color: #f8fafc; font-size: 20px; font-weight: 700; margin-top: 8px; }}

/* Checks Info */
.checks-info {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
               padding: 24px; margin-bottom: 24px; }}
.checks-info h2 {{ font-size: 20px; color: #f8fafc; margin-bottom: 16px; }}
.check-item {{ display: flex; align-items: center; gap: 8px; padding: 6px 0;
              font-size: 13px; }}
.check-run {{ color: #4ade80; }}
.check-skip {{ color: #f87171; }}

/* Footer */
.footer {{ text-align: center; color: #475569; font-size: 12px; padding: 24px;
          border-top: 1px solid #1e293b; }}

/* Toggle arrow */
.toggle-arrow {{ color: #64748b; font-size: 18px; transition: transform 0.2s; }}
.toggle-arrow.open {{ transform: rotate(90deg); }}

@media (max-width: 768px) {{
    .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .mitre-grid {{ grid-template-columns: 1fr; }}
    .header .meta {{ flex-wrap: wrap; }}
}}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
    <h1>🐤 Canary — Anti-Forensics Detection Report</h1>
    <div class="subtitle">Systematic analysis for evidence of tampering, log manipulation, and anti-forensic activity</div>
    <div class="meta">
        <span>📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        <span>⏱ Duration: {duration}</span>
        <span>🔍 Checks: {len(result.checks_run)} run, {len(result.checks_skipped)} skipped</span>
        <span>📊 Findings: {len(result.findings)}</span>
    </div>
</div>

<!-- Tampering Score -->
<div class="score-card">
    <div class="score-value">{score}</div>
    <div class="score-label">Tampering Score</div>
    <div class="score-grade">{self._score_grade(score)}</div>
</div>

<!-- Summary -->
<div class="summary-grid">
    <div class="summary-item">
        <div class="summary-count" style="color:#dc2626">{summary.get('critical', 0)}</div>
        <div class="summary-label">Critical</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#ea580c">{summary.get('high', 0)}</div>
        <div class="summary-label">High</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#ca8a04">{summary.get('medium', 0)}</div>
        <div class="summary-label">Medium</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#2563eb">{summary.get('low', 0)}</div>
        <div class="summary-label">Low</div>
    </div>
    <div class="summary-item">
        <div class="summary-count" style="color:#6b7280">{summary.get('info', 0)}</div>
        <div class="summary-label">Info</div>
    </div>
</div>

<!-- MITRE ATT&CK Mapping -->
{mitre_html}

<!-- Findings -->
<div class="findings">
    <h2>Detailed Findings ({len(result.findings)})</h2>
    {findings_html}
</div>

<!-- Checks Info -->
<div class="checks-info">
    <h2>Check Execution Summary</h2>
    {''.join(f'<div class="check-item check-run">✓ {c}</div>' for c in result.checks_run)}
    {''.join(f'<div class="check-item check-skip">⏭ {c}</div>' for c in result.checks_skipped)}
</div>

<!-- Footer -->
<div class="footer">
    Generated by Canary Anti-Forensics Detector v1.0.0 |
    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
    All analysis performed locally — no data transmitted
</div>

</div>

<script>
document.querySelectorAll('.finding-header').forEach(header => {{
    header.addEventListener('click', () => {{
        const body = header.nextElementSibling;
        const arrow = header.querySelector('.toggle-arrow');
        body.classList.toggle('open');
        arrow.classList.toggle('open');
    }});
}});
// Auto-expand critical findings
document.querySelectorAll('.finding[data-severity="critical"] .finding-body').forEach(b => {{
    b.classList.add('open');
    b.previousElementSibling.querySelector('.toggle-arrow').classList.add('open');
}});
</script>
</body>
</html>"""

    def _score_grade(self, score: int) -> str:
        if score >= 70:
            return "CRITICAL — Strong evidence of anti-forensic activity"
        elif score >= 40:
            return "HIGH — Multiple indicators of evidence tampering"
        elif score >= 20:
            return "MODERATE — Suspicious indicators found"
        elif score > 0:
            return "LOW — Minor anomalies detected"
        return "CLEAN — No anti-forensic indicators detected"

    def _build_findings_html(self) -> str:
        """Build HTML for all findings, sorted by severity."""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(
            self.result.findings,
            key=lambda f: severity_order.index(f.severity)
        )

        parts = []
        for i, finding in enumerate(sorted_findings):
            evidence_text = "\n".join(finding.evidence) if finding.evidence else "No detailed evidence available."
            mitre_tag = ""
            if finding.mitre_technique:
                mitre_tag = f'<span class="mitre-tag">{finding.mitre_technique}</span>'

            timestamp_str = ""
            if finding.timestamp:
                timestamp_str = f'<span>🕐 {finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</span>'

            parts.append(f"""
<div class="finding" data-severity="{finding.severity.value}">
    <div class="finding-header">
        <div class="finding-severity" style="background:{self._severity_color(finding.severity)}"></div>
        <div class="finding-title">
            <h3>{finding.title}</h3>
            <div class="meta">
                <span style="color:{self._severity_color(finding.severity)};font-weight:600;">
                    {finding.severity.value.upper()}
                </span>
                {self._confidence_badge(finding.confidence)}
                {mitre_tag}
                <span style="color:#94a3b8">{finding.category.value}</span>
                {timestamp_str}
            </div>
        </div>
        <span class="toggle-arrow">▶</span>
    </div>
    <div class="finding-body">
        <div class="finding-desc">{finding.description}</div>
        <div class="evidence-box">{self._escape_html(evidence_text)}</div>
        {f'<div class="recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>' if finding.recommendation else ''}
    </div>
</div>""")

        if not parts:
            return '<div style="text-align:center;color:#4ade80;padding:40px;">✓ No anti-forensic indicators detected</div>'
        return "\n".join(parts)

    def _build_mitre_html(self) -> str:
        """Build MITRE ATT&CK mapping section."""
        technique_counts: Dict[str, Dict] = {}

        for finding in self.result.findings:
            tid = finding.mitre_technique
            if not tid:
                continue
            if tid not in technique_counts:
                mapping = MITRE_MAPPING.get(finding.category, {})
                technique_counts[tid] = {
                    "name": mapping.get("technique_name", tid),
                    "tactic": mapping.get("tactic", ""),
                    "count": 0,
                }
            technique_counts[tid]["count"] += 1

        if not technique_counts:
            return ""

        cards = []
        for tid, info in sorted(technique_counts.items(), key=lambda x: -x[1]["count"]):
            cards.append(f"""
<div class="mitre-card">
    <div class="technique">{tid}</div>
    <div class="tactic">{info['tactic']}: {info['name']}</div>
    <div class="count">{info['count']} finding(s)</div>
</div>""")

        return f"""
<div class="mitre-section">
    <h2>MITRE ATT&CK Mapping</h2>
    <div class="mitre-grid">{''.join(cards)}</div>
</div>"""

    def _build_category_data(self) -> Dict[str, int]:
        """Build category count data."""
        counts: Dict[str, int] = {}
        for finding in self.result.findings:
            cat = finding.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
