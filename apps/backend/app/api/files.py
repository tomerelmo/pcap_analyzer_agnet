from fastapi import APIRouter, HTTPException
from app.models.requests import FileScanRequest
from app.models.responses import FileScanResponse
from app.services import mcp_client

router = APIRouter()


@router.post("/scan", response_model=FileScanResponse)
async def scan_files(request: FileScanRequest) -> FileScanResponse:
    """Scan a path for PCAP/PCAPNG files via the MCP server."""
    try:
        result = await mcp_client.list_pcaps(request.path)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return FileScanResponse(
        files=result.get("files", []),
        count=result.get("count", 0),
        path=result.get("path", request.path),
    )
