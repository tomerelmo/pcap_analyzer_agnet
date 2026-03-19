from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    # Ollama defaults
    ollama_base_url: str = Field(
        default="http://host.docker.internal:11434",
        alias="DEFAULT_OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(
        default="gpt-oss:20b",
        alias="DEFAULT_OLLAMA_MODEL",
    )

    # File paths
    allowed_pcap_roots: str = Field(
        default="/data/pcaps",
        alias="ALLOWED_PCAP_ROOTS",
    )
    reports_dir: str = Field(
        default="/data/reports",
        alias="REPORTS_DIR",
    )
    cache_dir: str = Field(
        default="/data/cache",
        alias="CACHE_DIR",
    )

    # Analysis limits
    max_packet_slice_results: int = Field(
        default=200,
        alias="MAX_PACKET_SLICE_RESULTS",
    )
    max_stream_extract_chars: int = Field(
        default=20000,
        alias="MAX_STREAM_EXTRACT_CHARS",
    )
    analysis_timeout_seconds: int = Field(
        default=120,
        alias="ANALYSIS_TIMEOUT_SECONDS",
    )

    # Test / misc
    ollama_test_prompt: str = Field(
        default="Reply with exactly: OLLAMA_OK",
        alias="OLLAMA_TEST_PROMPT",
    )
    mcp_server_url: str = Field(
        default="http://mcp-server:8001",
        alias="MCP_SERVER_URL",
    )
    log_level: str = Field(
        default="INFO",
        alias="LOG_LEVEL",
    )

    model_config = {"populate_by_name": True, "env_file": ".env"}


settings = Settings()
