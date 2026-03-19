import time
import logging
from typing import Optional

import httpx

from app.config import settings
from app.models.responses import OllamaTestResponse

logger = logging.getLogger(__name__)


async def test_connection(base_url: str, model: str) -> OllamaTestResponse:
    """Test Ollama connectivity, model availability, and run a quick generation."""
    base_url = base_url.rstrip("/")

    # Step 1: Check server reachability and list models
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            tags_resp = await client.get(f"{base_url}/api/tags")
            tags_resp.raise_for_status()
            tags_data = tags_resp.json()
    except httpx.ConnectError:
        return OllamaTestResponse(
            success=False,
            reason=f"Cannot connect to Ollama at {base_url}. Is it running?",
        )
    except httpx.TimeoutException:
        return OllamaTestResponse(
            success=False,
            reason=f"Connection timed out reaching {base_url}",
        )
    except httpx.HTTPStatusError as e:
        return OllamaTestResponse(
            success=False,
            reason=f"Ollama returned HTTP {e.response.status_code}",
        )
    except Exception as e:
        return OllamaTestResponse(
            success=False,
            reason=f"Unexpected error contacting Ollama: {e}",
        )

    # Step 2: Check model existence
    available_models = [m.get("name", "") for m in tags_data.get("models", [])]
    model_found = model in available_models or any(
        m.startswith(model) for m in available_models
    )

    if not model_found:
        available_str = ", ".join(available_models) if available_models else "none"
        return OllamaTestResponse(
            success=False,
            reason=(
                f"Model '{model}' not found on this Ollama instance. "
                f"Available: {available_str}"
            ),
        )

    # Step 3: Run a small test generation
    try:
        start = time.monotonic()
        async with httpx.AsyncClient(timeout=60.0) as client:
            gen_resp = await client.post(
                f"{base_url}/api/generate",
                json={
                    "model": model,
                    "prompt": settings.ollama_test_prompt,
                    "stream": False,
                },
            )
            gen_resp.raise_for_status()
        elapsed_ms = (time.monotonic() - start) * 1000
        gen_data = gen_resp.json()
        response_text = gen_data.get("response", "").strip()
        logger.info("Ollama test generation succeeded: %r", response_text)
        return OllamaTestResponse(
            success=True,
            reason=f"Model responded: {response_text[:100]}",
            latency_ms=round(elapsed_ms, 1),
            model_name=model,
        )
    except httpx.TimeoutException:
        return OllamaTestResponse(
            success=False,
            reason=f"Model '{model}' found but generation timed out. It may still be loading.",
            model_name=model,
        )
    except httpx.HTTPStatusError as e:
        return OllamaTestResponse(
            success=False,
            reason=f"Generation request failed with HTTP {e.response.status_code}",
            model_name=model,
        )
    except Exception as e:
        return OllamaTestResponse(
            success=False,
            reason=f"Generation error: {e}",
            model_name=model,
        )


async def generate(
    base_url: str,
    model: str,
    prompt: str,
    system: Optional[str] = None,
) -> str:
    """Send a generation request to Ollama and return the response text."""
    base_url = base_url.rstrip("/")
    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if system:
        payload["system"] = system

    try:
        async with httpx.AsyncClient(timeout=settings.analysis_timeout_seconds + 30.0) as client:
            resp = await client.post(f"{base_url}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")
    except httpx.TimeoutException:
        raise RuntimeError(f"Ollama generation timed out after {settings.analysis_timeout_seconds}s")
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Ollama returned HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        raise RuntimeError(f"Ollama generate error: {e}")
