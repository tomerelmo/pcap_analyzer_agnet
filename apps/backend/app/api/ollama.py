from fastapi import APIRouter
from app.models.requests import OllamaTestRequest
from app.models.responses import OllamaTestResponse
from app.services import ollama_service

router = APIRouter()


@router.post("/test", response_model=OllamaTestResponse)
async def test_ollama(request: OllamaTestRequest) -> OllamaTestResponse:
    """Test Ollama connectivity, model availability, and run a small generation."""
    return await ollama_service.test_connection(
        base_url=request.base_url,
        model=request.model,
    )
