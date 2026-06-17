from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from src.api import deps
from src.models.models import Workspace
from src.services.pdf_report_service import PDFReportService

router = APIRouter()


@router.get("/security-report")
async def download_security_report(
    hours: int = 0,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Response:
    pdf_bytes = PDFReportService.generate_security_report(db, workspace, hours=hours)
    filename = f"cyberguard-security-report-{workspace.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
