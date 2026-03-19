import uuid
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# In-memory session store: {session_id: session_dict}
_sessions: dict[str, dict] = {}


def create_session(
    ollama_config: dict,
    file_path: str,
    goal: str,
    options: dict,
) -> str:
    """Create a new analysis session and return the session ID."""
    session_id = str(uuid.uuid4())
    _sessions[session_id] = {
        "id": session_id,
        "status": "pending",
        "progress": None,
        "report": None,
        "ollama_config": ollama_config,
        "file_path": file_path,
        "goal": goal,
        "options": options,
    }
    logger.info("Created session %s for file %s", session_id, file_path)
    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """Retrieve a session by ID. Returns None if not found."""
    return _sessions.get(session_id)


def update_session(
    session_id: str,
    status: Optional[str] = None,
    progress: Optional[str] = None,
    report: Optional[dict] = None,
) -> None:
    """Update mutable fields of a session."""
    session = _sessions.get(session_id)
    if session is None:
        logger.warning("update_session called for unknown session %s", session_id)
        return
    if status is not None:
        session["status"] = status
    if progress is not None:
        session["progress"] = progress
    if report is not None:
        session["report"] = report
    logger.debug(
        "Session %s updated: status=%s progress=%s",
        session_id,
        session.get("status"),
        session.get("progress"),
    )
