"""Report export (implemented in Phase 5).

The route exists so the UI can link to it from day one; it reports a clear
"not yet available" state instead of failing silently.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

router = APIRouter()


@router.get("/analyses/{analysis_id}/report", name="analysis_report")
def analysis_report(analysis_id: int):
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Report export arrives in Phase 5.",
    )
