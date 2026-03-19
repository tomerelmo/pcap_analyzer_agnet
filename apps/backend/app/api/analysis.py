import asyncio
import logging

from fastapi import APIRouter, HTTPException, BackgroundTasks

from app.models.requests import AnalysisStartRequest
from app.models.responses import AnalysisStartResponse, AnalysisStatusResponse, AnalysisReport
from app.services import session_service, analysis_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/start", response_model=AnalysisStartResponse)
async def start_analysis(
    request: AnalysisStartRequest,
    background_tasks: BackgroundTasks,
) -> AnalysisStartResponse:
    """Create an analysis session and kick off background processing."""
    session_id = session_service.create_session(
        ollama_config=request.ollama.model_dump(),
        file_path=request.file_path,
        goal=request.goal,
        options=request.options.model_dump(),
    )

    # Launch the analysis as a background task
    background_tasks.add_task(
        _run_analysis_task,
        session_id=session_id,
        request=request,
    )

    return AnalysisStartResponse(analysis_id=session_id, status="running")


async def _run_analysis_task(session_id: str, request: AnalysisStartRequest) -> None:
    """Wrapper to run analysis in the background."""
    try:
        await analysis_service.run_analysis(session_id, request)
    except Exception as e:
        logger.exception("Background analysis task failed for session %s: %s", session_id, e)
        session_service.update_session(
            session_id,
            status="failed",
            progress=f"Internal error: {e}",
        )


@router.get("/{analysis_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(analysis_id: str) -> AnalysisStatusResponse:
    """Return the current status and report (if complete) for an analysis."""
    session = session_service.get_session(analysis_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found")

    report = None
    raw_report = session.get("report")
    if raw_report is not None:
        try:
            report = AnalysisReport.model_validate(raw_report)
        except Exception as e:
            logger.warning("Could not parse report for session %s: %s", analysis_id, e)

    return AnalysisStatusResponse(
        analysis_id=analysis_id,
        status=session.get("status", "unknown"),
        progress=session.get("progress"),
        report=report,
    )
