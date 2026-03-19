from pydantic import BaseModel
from typing import Optional


class OllamaTestResponse(BaseModel):
    success: bool
    reason: str
    latency_ms: Optional[float] = None
    model_name: Optional[str] = None


class FileScanResponse(BaseModel):
    files: list[str]
    count: int
    path: str


class AnalysisStartResponse(BaseModel):
    analysis_id: str
    status: str


class Evidence(BaseModel):
    stream_ids: list[int] = []
    packet_numbers: list[int] = []
    filter: Optional[str] = None


class Finding(BaseModel):
    title: str
    confidence: str
    explanation: str
    evidence: Evidence = Evidence()


class AnalysisReport(BaseModel):
    summary: str
    findings: list[Finding] = []
    suspicious_streams: list[dict] = []
    open_questions: list[str] = []
    next_steps: list[str] = []


class AnalysisStatusResponse(BaseModel):
    analysis_id: str
    status: str
    progress: Optional[str] = None
    report: Optional[AnalysisReport] = None
