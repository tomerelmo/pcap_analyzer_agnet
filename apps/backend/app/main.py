import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.api import ollama, files, analysis

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PCAP Analyzer Backend",
    description="Local-first PCAP analysis backend using Ollama and MCP tools",
    version="1.0.0",
)

# CORS: allow Streamlit frontend and local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tightened in production via env if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(ollama.router, prefix="/api/ollama", tags=["ollama"])
app.include_router(files.router, prefix="/api/files", tags=["files"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])


@app.get("/health", tags=["health"])
async def health_check():
    return {
        "status": "ok",
        "mcp_server_url": settings.mcp_server_url,
        "allowed_pcap_roots": settings.allowed_pcap_roots,
    }


@app.on_event("startup")
async def startup():
    logger.info("PCAP Analyzer backend starting up")
    logger.info("MCP server URL: %s", settings.mcp_server_url)
    logger.info("Allowed PCAP roots: %s", settings.allowed_pcap_roots)
