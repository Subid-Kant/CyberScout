"""
scanner/report_gen.py
Generates a professional PDF vulnerability assessment report.
Upgraded: Risk Score (0-100), executive summary table, color-coded findings,
          cover page, disclaimer page.
"""

import os
import datetime
from pathlib import Path
from utils.logger import setup_logger
from utils.helpers import calculate_risk_score

logger = setup_logger("report_gen")

SEVERITY_COLORS = {
    "critical": (220, 53,  69),
    "high":     (255, 102,  0),
    "medium":   (255, 193,  7),
    "low":      (40,  167, 69),
    "info":     (23,  162, 184),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportGenerator:
    def __init__(self, scan_id: str, findings: list, target: str = ""):
        self.scan_id    = scan_id
        self.findings   = findings
        self.target     = target
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)

    def get_summary(self) -> dict:
        summary = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    # ── PDF generation ───────────────────────────────────────────────────────

    def generate(self) -> str:
        try:
            from fpdf import FPDF
        except ImportError:
            logger.warning("fpdf2 not installed. Generating text report.")
            return self._generate_text_report()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        self._cover_page(pdf)
        self._exec_summary_page(pdf)
        self._findings_pages(pdf)
        self._disclaimer_page(pdf)

        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = str(self.report_dir / f"cyberscout_{self.scan_id}_{ts}.pdf")
        pdf.output(filename)
        logger.info(f"PDF report saved: {filename}")
        return filename

    # ── Cover page ────────────────────────────────────────────────────────────

    def _cover_page(self, pdf):
        pdf.add_page()

        # Dark header band
        pdf.set_fill_color(20, 25, 45)
        pdf.rect(0, 0, 210, 297, "F")

        # Title
        pdf.set_font("Helvetica", "B", 30)
        pdf.set_text_color(0, 200, 180)
        pdf.set_xy(15, 90)
        pdf.cell(0, 15, "CyberScout", ln=True, align="C")

        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(220, 220, 220)
        pdf.set_xy(15, 112)
        pdf.cell(0, 10, "Vulnerability Assessment Report", ln=True, align="C")

        # Divider
        pdf.set_draw_color(0, 200, 180)
        pdf.set_line_width(0.5)
        pdf.line(40, 128, 170, 128)

        # Metadata
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(180, 180, 180)
        meta = [
            ("Scan ID",   self.scan_id),
            ("Target",    self.target or "N/A"),
            ("Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")),
            ("Findings",  str(len(self.findings))),
        ]
        y = 140
        for label, val in meta:
            pdf.set_xy(50, y)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(0, 200, 180)
            pdf.cell(45, 8, f"{label}:", ln=False)
            pdf.set_font("Helvetica", "", 11)
            pdf.set_text_color(220, 220, 220)
            pdf.cell(0, 8, val, ln=True)
            y += 10

        # Risk score badge
        score = calculate_risk_score(self.findings)
        if score >= 70:
            badge_color = (220, 53, 69)
            risk_label  = "HIGH RISK"
        elif score >= 40:
            badge_color = (255, 102, 0)
            risk_label  = "MEDIUM RISK"
        else:
            badge_color = (40, 167, 69)
            risk_label  = "LOW RISK"

        pdf.set_fill_color(*badge_color)
        pdf.rect(75, 215, 60, 28, "F")
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(75, 218)
        pdf.cell(60, 10, str(score), ln=True, align="C")
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_xy(75, 230)
        pdf.cell(60, 8, risk_label, ln=True, align="C")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(160, 160, 160)
        pdf.set_xy(75, 246)
        pdf.cell(60, 6, "Risk Score (0–100)", ln=True, align="C")

    # ── Executive summary ─────────────────────────────────────────────────────

    def _exec_summary_page(self, pdf):
        pdf.add_page()
        summary = self.get_summary()
        score   = calculate_risk_score(self.findings)

        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(20, 25, 45)
        pdf.cell(0, 12, "Executive Summary", ln=True)
        pdf.set_draw_color(0, 200, 180)
        pdf.set_line_width(0.4)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

        # Risk score summary sentence
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(50, 50, 50)
        total_non_info = sum(summary[s] for s in ["critical", "high", "medium", "low"])
        pdf.multi_cell(0, 7,
            f"This assessment identified {len(self.findings)} total findings across "
            f"{total_non_info} actionable issues. The overall risk score is {score}/100.",
            align="L"
        )
        pdf.ln(4)

        # Summary table
        col_w = [40, 30, 100]
        headers = ["Severity", "Count", "Recommended Action"]
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(20, 25, 45)
        pdf.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 9, f"  {h}", fill=True, border=1)
        pdf.ln()

        actions = {
            "critical": "Patch/mitigate within 24 hours",
            "high":     "Remediate within 7 days",
            "medium":   "Schedule fix within 30 days",
            "low":      "Address in next sprint",
            "info":     "Review for awareness",
        }
        for sev in SEVERITY_ORDER:
            r, g, b = SEVERITY_COLORS[sev]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(col_w[0], 8, f"  {sev.upper()}", fill=True, border=1)

            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(col_w[1], 8, f"  {summary[sev]}", fill=True, border=1)
            pdf.cell(col_w[2], 8, f"  {actions[sev]}", fill=True, border=1)
            pdf.ln()

        pdf.ln(8)

        # Severity breakdown bar chart (text-based)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(20, 25, 45)
        pdf.cell(0, 10, "Severity Distribution", ln=True)

        max_count = max(summary.values()) or 1
        bar_max_w = 120
        for sev in SEVERITY_ORDER:
            count = summary[sev]
            bar_w = int((count / max_count) * bar_max_w) if count else 0
            r, g, b = SEVERITY_COLORS[sev]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(30, 7, f"  {sev.upper()}", fill=True)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(50, 50, 50)
            if bar_w > 0:
                pdf.set_fill_color(r, g, b)
                pdf.cell(bar_w, 7, "", fill=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 7, f"  {count}", ln=True)

    # ── Detailed findings pages ───────────────────────────────────────────────

    def _findings_pages(self, pdf):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(20, 25, 45)
        pdf.cell(0, 12, "Detailed Findings", ln=True)
        pdf.set_draw_color(0, 200, 180)
        pdf.set_line_width(0.4)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

        # Sort by severity
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: order.get(f.get("severity", "info"), 99)
        )

        for finding in sorted_findings:
            sev  = finding.get("severity", "info")
            r, g, b = SEVERITY_COLORS.get(sev, (100, 100, 100))

            # Header bar
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 8, f"  [{sev.upper()}]  {finding.get('title', 'Finding')[:85]}", fill=True, ln=True)

            pdf.set_text_color(30, 30, 30)
            pdf.ln(2)

            for label, key in [
                ("Description",     "description"),
                ("Recommendation",  "recommendation"),
                ("Evidence",        "evidence"),
            ]:
                text = finding.get(key, "")
                if not text:
                    continue
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(38, 5.5, f"  {label}:", ln=False)
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5.5, str(text)[:250])

            pdf.ln(2)
            pdf.set_draw_color(210, 210, 210)
            pdf.set_line_width(0.2)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

    # ── Disclaimer ────────────────────────────────────────────────────────────

    def _disclaimer_page(self, pdf):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(20, 25, 45)
        pdf.cell(0, 12, "Disclaimer & Legal Notice", ln=True)
        pdf.set_draw_color(0, 200, 180)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 7,
            "This report was generated by CyberScout for authorized security assessment purposes only. "
            "All findings should be verified manually by a qualified security professional before "
            "remediation is undertaken. False positives are possible; critical findings especially "
            "should be corroborated by a second method.\n\n"
            "CyberScout is intended for use on systems you own or have explicit written permission to test. "
            "Unauthorized use against systems you do not own is strictly prohibited and may constitute "
            "a criminal offence under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, "
            "or equivalent legislation in your jurisdiction.\n\n"
            "The authors and contributors of CyberScout accept no liability for any damage, data loss, "
            "legal action, or other consequence arising from use or misuse of this tool. "
            "Use responsibly and ethically."
        )

    # ── Text fallback ─────────────────────────────────────────────────────────

    def _generate_text_report(self) -> str:
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = str(self.report_dir / f"cyberscout_{self.scan_id}_{ts}.txt")
        summary  = self.get_summary()
        score    = calculate_risk_score(self.findings)

        lines = [
            "=" * 70,
            "  CyberScout — Vulnerability Assessment Report",
            "=" * 70,
            f"  Scan ID    : {self.scan_id}",
            f"  Target     : {self.target or 'N/A'}",
            f"  Date       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Risk Score : {score}/100",
            "=" * 70,
            "",
            "SUMMARY",
            *[f"  {k.upper()}: {v}" for k, v in summary.items()],
            "",
            "FINDINGS",
            "-" * 70,
        ]
        for f in self.findings:
            lines += [
                f"[{f.get('severity','info').upper()}] {f.get('title','')}",
                f"  Description    : {f.get('description','')}",
                f"  Recommendation : {f.get('recommendation','')}",
                f"  Evidence       : {f.get('evidence','')}",
                "-" * 70,
            ]
        with open(filename, "w") as fp:
            fp.write("\n".join(lines))
        return filename
