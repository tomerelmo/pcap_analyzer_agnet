# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Local Portable PCAP Analysis Agent — a fully local-first, containerized packet-capture analysis system. All analysis happens locally; no data leaves the machine. The LLM backend is an external Ollama instance (not bundled).

## Commands

```bash
# Start the full stack
docker compose up --build

# Start in detached mode
docker compose up -d --build

# Restart a single service
docker compose up --build frontend
docker compose up --build backend
docker compose up --build mcp-server

# View logs
docker compose logs -f backend
docker compose logs -f mcp-server

# Run MCP server unit tests (once implemented)
docker compose run --rm mcp-server pytest mcp/server/tests/

# Run backend unit tests
docker compose run --rm backend pytest apps/backend/

# Tear down
docker compose down
```

## Architecture

Three containerized Python services + external Ollama:

```
frontend  (Streamlit, port 8501)
  ↕ REST
backend   (FastAPI, port 8000)
  ↕ REST        ↕ MCP protocol
              mcp-server  (Python MCP, internal)
                  ↕ subprocess
              tshark / capinfos  (inside mcp-server container)

Ollama    (external, user-configured URL)
```

### Service responsibilities

**`apps/frontend/app.py`** — Streamlit UI. Four screens in sequence:
1. Ollama Setup (URL + model + test connection — gated, must succeed before proceeding)
2. Capture Selection (browse mounted `/data/pcaps`)
3. Investigation Setup (free-text goal + analysis options)
4. Results View (findings, evidence, Wireshark filters, export)

**`apps/backend/app/`** — FastAPI backend. Key modules:
- `services/ollama_service.py` — connectivity test + LLM calls
- `services/mcp_client.py` — calls MCP server tools
- `services/analysis_service.py` — orchestrates staged analysis
- `services/session_service.py` — per-session Ollama config
- `services/report_service.py` — formats final findings
- `config.py` — reads env vars

Key endpoints: `POST /api/ollama/test`, `POST /api/files/scan`, `POST /api/analysis/start`, `GET /api/analysis/{id}`, `GET /api/analysis/{id}/report`

**`mcp/server/`** — Python MCP server. Wraps bounded tshark/capinfos subprocesses. Tools live in `tools/`:
- `files.py`: `validate_pcap_path`, `list_pcaps`, `describe_capture`
- `helpers.py`: `packet_slice`, `run_tshark_fields`, `run_tshark_stat`, `parse_fields_output`
- `metadata.py`: `get_conversations`, `get_endpoints`, `get_protocol_hierarchy`, `get_io_stats`, `get_expert_info`
- `tcp.py`: `find_resets`, `find_retransmissions`, `find_zero_windows`, `find_duplicate_acks`, `find_long_lived_connections`, `get_tcp_summary`, `follow_tcp_stream`
- `http.py`: `http_summary`, `http_errors`, `http_response_times`, `requests_without_response`, `http_top_uris`
- `tls.py`: `tls_handshake_summary`, `tls_alerts`, `tls_certificate_info`
- `dns.py`: `dns_summary`, `dns_failed_queries`, `dns_suspicious_patterns`, `dns_response_times`
- `security.py`: `detect_port_scan`, `detect_beaconing`, `find_cleartext_credentials`, `detect_data_exfiltration`, `get_expert_info`
- `performance.py`: `get_service_response_times`, `get_throughput_analysis`, `find_slow_connections`, `get_connection_stats`
- `network.py`: `dhcp_summary`, `arp_analysis`, `icmp_analysis`, `smb_summary`

The MCP server exposes all tools via `POST /tools/{tool_name}` and lists them at `GET /tools`.

### File access model

Host PCAP directory is mounted into backend and mcp-server at `/data/pcaps`. All paths are validated against `ALLOWED_PCAP_ROOTS` — reject traversal attempts and paths outside allowed roots. Reports go to `/data/reports`, cache to `/data/cache`.

### Analysis strategy (critical)

Never pass raw PCAP bytes to the LLM. Always use staged tool calls:
1. Validate file → read metadata → get conversation summaries
2. Identify suspicious candidates via pattern detection tools
3. Drill into only relevant streams
4. Produce structured findings: confirmed facts / likely explanations / unknowns

### MCP tool constraints

Every tool must: validate path before use, enforce subprocess timeouts, truncate output (max `MAX_PACKET_SLICE_RESULTS=200` packets, `MAX_STREAM_EXTRACT_CHARS=20000` chars), return deterministic JSON, handle broken captures gracefully. No arbitrary shell execution.

## Configuration

Copy `.env.example` to `.env`. Key variables:

```
BACKEND_PORT=8000
FRONTEND_PORT=8501
DEFAULT_OLLAMA_BASE_URL=http://host.docker.internal:11434
DEFAULT_OLLAMA_MODEL=gpt-oss:20b
ALLOWED_PCAP_ROOTS=/data/pcaps
REPORTS_DIR=/data/reports
CACHE_DIR=/data/cache
MAX_PACKET_SLICE_RESULTS=200
MAX_STREAM_EXTRACT_CHARS=20000
ANALYSIS_TIMEOUT_SECONDS=120
OLLAMA_TEST_PROMPT=Reply with exactly: OLLAMA_OK
```

Ollama URL examples by environment:
- macOS host: `http://host.docker.internal:11434`
- Linux host: `http://172.17.0.1:11434`
- Remote machine: `http://192.168.x.x:11434`

## Implementation Notes

- Python everywhere — no JavaScript, no Node
- All subprocess calls to tshark/capinfos must use explicit argument lists (not shell=True)
- MCP tool JSON output must be typed and stable — the LLM depends on consistent schemas
- Ollama connectivity test is a first-class gating feature, not optional
- Portability: no hardcoded paths, no username assumptions, all config via env vars or UI

## Build Phases

- **Phase 1** (complete): Core stack + Ollama test + file scan + `validate_pcap_path`, `list_pcaps`, `describe_capture`, `get_conversations`, `find_resets` + first report
- **Phase 2** (complete): TCP deep-dive (`find_retransmissions`, `find_zero_windows`, `find_duplicate_acks`, `find_long_lived_connections`, `get_tcp_summary`) + HTTP (`http_summary`, `http_errors`, `http_response_times`, `requests_without_response`, `http_top_uris`)
- **Phase 3** (complete): TLS (`tls_handshake_summary`, `tls_alerts`, `tls_certificate_info`), DNS (`dns_summary`, `dns_failed_queries`, `dns_suspicious_patterns`, `dns_response_times`), stream follow (`follow_tcp_stream`), packet slice, metadata extensions (`get_endpoints`, `get_protocol_hierarchy`, `get_io_stats`, `get_expert_info`), security analysis (`detect_port_scan`, `detect_beaconing`, `find_cleartext_credentials`, `detect_data_exfiltration`), performance (`get_service_response_times`, `get_throughput_analysis`, `find_slow_connections`, `get_connection_stats`), network (`dhcp_summary`, `arp_analysis`, `icmp_analysis`, `smb_summary`)
- **Phase 4**: Export, saved sessions, caching, capture comparison
