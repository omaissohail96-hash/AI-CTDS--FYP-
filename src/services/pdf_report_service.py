from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from io import BytesIO
from textwrap import wrap
from typing import Any, Dict, Iterable, List

from sqlalchemy.orm import Session

from src.models.models import ScanHistory, Workspace


class PDFReportService:
    """
    Dependency-free PDF generator for executive IDS assessment reports.
    Produces a clean text-first report suitable for demos and academic review.
    """

    @staticmethod
    def generate_security_report(db: Session, workspace: Workspace, hours: int = 0, limit: int = 250) -> bytes:
        query = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace.id
        )
        if hours > 0:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(ScanHistory.created_at >= cutoff)
            
        scans = query.order_by(ScanHistory.created_at.desc()).limit(limit).all()

        lines = PDFReportService._build_report_lines(workspace, scans, hours)
        return PDFReportService._render_pdf(lines)

    @staticmethod
    def _build_report_lines(workspace: Workspace, scans: Iterable[ScanHistory], hours: int = 0) -> List[str]:
        scans = list(scans)
        total_scans = len(scans)
        severity_counts = Counter((scan.verdict or "UNKNOWN").upper() for scan in scans)
        attack_counts = Counter(scan.attack_type or "UNKNOWN" for scan in scans)
        risk_scores = [int(scan.risk_score or 0) for scan in scans]
        critical_scans = [scan for scan in scans if (scan.verdict or "").upper() == "CRITICAL" or (scan.risk_score or 0) >= 86]
        intel_hits = [scan for scan in scans if scan.intelligence_hit]
        mitre_counter = Counter()
        for scan in scans:
            for mapping in scan.mitre_mappings or []:
                mitre_counter[f"{mapping.get('technique_id')} {mapping.get('technique')}"] += 1

        range_str = "All Time" if hours == 0 else f"Last {hours} Hours"
        lines = [
            "CyberGuard AI Security Assessment Report",
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "Workspace",
            f"Organization: {workspace.name}",
            f"Workspace ID: {workspace.id}",
            f"Tier: {workspace.tier}",
            f"Report Range: {range_str}",
            "",
            "Threat Summary",
            f"Total scans analyzed: {total_scans}",
            f"Average risk score: {round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0}",
            f"Maximum risk score: {max(risk_scores) if risk_scores else 0}",
            f"Critical incidents: {len(critical_scans)}",
            f"Threat intelligence hits: {len(intel_hits)}",
            "",
            "Threat Distribution",
        ]

        for severity, count in sorted(severity_counts.items()):
            lines.append(f"- {severity}: {count}")

        lines.extend(["", "Top Attack Categories"])
        for attack_type, count in attack_counts.most_common(8):
            lines.append(f"- {attack_type}: {count}")

        lines.extend(["", "MITRE ATT&CK Mapping"])
        if mitre_counter:
            for label, count in mitre_counter.most_common(8):
                lines.append(f"- {label}: {count} related detections")
        else:
            lines.append("- No ATT&CK techniques mapped yet.")

        lines.extend(["", "Critical Incidents"])
        if critical_scans:
            for scan in critical_scans[:10]:
                lines.append(
                    f"- {scan.created_at}: {scan.input_type} | {scan.entity} | "
                    f"{scan.attack_type} | risk {scan.risk_score}"
                )
        else:
            lines.append("- No critical incidents in the selected report window.")

        lines.extend(["", "Threat Intelligence Findings"])
        if intel_hits:
            for scan in intel_hits[:10]:
                lines.append(f"- {scan.entity}: {scan.attack_type} ({scan.verdict}, risk {scan.risk_score})")
        else:
            lines.append("- No direct threat intelligence matches were observed.")

        lines.extend([
            "",
            "Recommendations",
            "- Review all HIGH and CRITICAL detections before closing alerts.",
            "- Use threat hunting to pivot on repeated IPs, domains, URLs, and email indicators.",
            "- Validate exposed web application controls for SQL injection, XSS, and traversal detections.",
            "- Preserve scan history and explanations as investigation evidence.",
            "- Keep IDS actions observational; avoid automatic blocking in this workflow.",
            "",
            "Recent Scan History",
        ])
        for scan in scans[:25]:
            explanation = (scan.explanation or {}).get("explanation", "")
            lines.append(
                f"- {scan.created_at}: {scan.input_type} | {scan.entity} | "
                f"{scan.attack_type or 'UNKNOWN'} | {scan.verdict} | risk {scan.risk_score}"
            )
            if explanation:
                lines.append(f"  Explanation: {explanation}")

        return lines

    @staticmethod
    def _render_pdf(lines: List[str]) -> bytes:
        pages: List[str] = []
        current: List[str] = []
        for line in lines:
            wrapped = wrap(line, width=92) or [""]
            for part in wrapped:
                current.append(part)
                if len(current) >= 48:
                    pages.append(PDFReportService._page_stream(current))
                    current = []
        if current:
            pages.append(PDFReportService._page_stream(current))

        objects: List[bytes] = []
        page_refs = []

        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objects.append(b"")
        font_obj_id = 3
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        for stream in pages:
            content_id = len(objects) + 2
            page_id = len(objects) + 1
            page_refs.append(f"{page_id} 0 R")
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_obj_id} 0 R >> >> /Contents {content_id} 0 R >>".encode()
            )
            stream_bytes = stream.encode("latin-1", errors="replace")
            objects.append(
                f"<< /Length {len(stream_bytes)} >>\nstream\n".encode() + stream_bytes + b"\nendstream"
            )

        objects[1] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode()

        buffer = BytesIO()
        buffer.write(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(buffer.tell())
            buffer.write(f"{index} 0 obj\n".encode())
            buffer.write(obj)
            buffer.write(b"\nendobj\n")

        xref_offset = buffer.tell()
        buffer.write(f"xref\n0 {len(objects) + 1}\n".encode())
        buffer.write(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            buffer.write(f"{offset:010d} 00000 n \n".encode())
        buffer.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode()
        )
        return buffer.getvalue()

    @staticmethod
    def _page_stream(lines: List[str]) -> str:
        y = 748
        commands = ["BT", "/F1 11 Tf", "50 748 Td"]
        for index, line in enumerate(lines):
            if index:
                commands.append("0 -14 Td")
            font_size = 16 if line == "CyberGuard AI Security Assessment Report" else 11
            commands.append(f"/F1 {font_size} Tf")
            commands.append(f"({PDFReportService._escape(line)}) Tj")
            y -= 14
        commands.append("ET")
        return "\n".join(commands)

    @staticmethod
    def _escape(text: Any) -> str:
        return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
