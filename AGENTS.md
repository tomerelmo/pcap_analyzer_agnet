# AGENTS.md

## Project Name
Local Portable PCAP Analysis Agent

## Goal
Build a fully local-first, portable packet-capture analysis system that can run on any computer with:
- Docker
- a local or reachable Ollama instance
- access to packet capture files

The system must:
- analyze `.pcap` / `.pcapng` files locally
- keep traffic data local
- use an MCP server for packet-analysis tools
- provide a Python-based frontend
- allow the user to configure the Ollama endpoint and model from the UI
- test Ollama connectivity before starting any investigation

This project should be easy to move between machines with minimal changes.

---

## Updated Core Requirements

### Privacy / Local-Only
- PCAP data must never leave the user’s computer or local environment.
- No cloud LLM APIs.
- No packet capture upload to external services.
- All analysis must happen locally through local containers and a local/reachable Ollama endpoint.

### Portability
The system should be portable between different computers.

The design must assume:
- different host machines may have different paths
- Ollama may run:
  - on the host machine
  - on another machine in the same network
  - at any configurable URL reachable from the containers

Therefore:
- Ollama base URL must be configurable from the UI and backend config
- model name must be configurable from the UI
- the app should include an Ollama connection test workflow
- file path handling must be explicit and predictable

### Platform
Primary target:
- macOS Apple Silicon
But design should remain portable enough to work on:
- Linux
- Windows with Docker Desktop
- other Macs

### Deployment Style
For v1:
- frontend in Docker
- backend in Docker
- MCP server in Docker
- Ollama stays external to the app stack and is configured by URL

This means the app stack is containerized, but Ollama is treated as an external local dependency.

### Frontend Language
Frontend must be implemented in Python.

Recommended frontend choices:
- Streamlit for fastest delivery
- NiceGUI if a more app-like UX is desired
- Gradio only if it remains structured enough for analyst workflows

Preferred v1 choice:
- **Streamlit**

### Backend Language
- Python

### MCP Server Language
- Python

### Model
Default target:
- `gpt-oss:20b`

The user must be able to override this from the UI.

---

## Product Vision

This product is a portable local analyst assistant for packet captures.

The user experience should be:

1. Open the UI
2. Configure Ollama connection:
   - base URL
   - model name
3. Click **Test Ollama Connection**
4. Confirm that the selected model is reachable and working
5. Enter a path to a PCAP file or folder
6. Select a file
7. Describe the analysis objective
8. Run investigation
9. Receive:
   - capture summary
   - suspicious flows
   - likely causes
   - packet/timestamp evidence
   - Wireshark filters to reproduce findings

The app should feel like a practical troubleshooting workstation, not a generic chat toy.

---

## Non-Goals for v1
Do **not** attempt:
- Kubernetes deployment
- multi-user auth
- cloud sync
- SIEM integration
- packet replay / injection
- unrestricted shell access for the LLM
- full support for every protocol in Wireshark
- remote storage
- browser-only frontend with JS requirement
- direct raw-PCAP ingestion into the model

---

## High-Level Architecture

### Main Components

#### 1. Python Frontend Container
The frontend is a Python web UI.

Recommended framework:
- **Streamlit**

The frontend should allow the user to:
- configure Ollama URL
- configure model name
- test Ollama connection
- enter a PCAP folder path or file path
- browse discovered captures
- enter investigation goal text
- run an analysis
- view results
- export report

#### 2. Python Backend Container
A backend service that:
- exposes REST endpoints
- validates requests
- manages analysis sessions
- calls Ollama
- calls the MCP server
- stores results
- formats final findings

Recommended framework:
- **FastAPI**

#### 3. Python MCP Server Container
The MCP server runs in Docker and exposes bounded packet-analysis tools.

It wraps:
- file validation
- capture discovery
- `capinfos`
- `tshark`
- selected parsing helpers

It must **not** expose unrestricted shell execution.

#### 4. External Ollama
Ollama is not bundled into the app stack for v1.

Instead:
- the user provides the Ollama URL in the UI
- the backend uses that URL for model calls
- the app supports any reachable Ollama host

Examples:
- `http://host.docker.internal:11434`
- `http://192.168.1.50:11434`
- `http://localhost:11434` (depending on runtime environment)

This supports the “mobility style” requirement.

---

## Deployment Philosophy

### Mobility Style
The system should be movable between computers with minimal work.

That means:
- all app logic lives in Docker containers
- only Ollama and packet files are host/environment-specific
- configuration is externalized
- no machine-specific hardcoding
- no assumptions about usernames or filesystem layout

### Portability Principles
- use environment variables
- use UI-configured runtime values
- avoid hardcoded paths
- keep mounts explicit
- treat file paths as user-specified runtime inputs

---

## Recommended Runtime Layout

### Containerized Services
- `frontend` (Streamlit)
- `backend` (FastAPI)
- `mcp-server` (Python MCP server)

### External Dependency
- `ollama` at user-specified URL

### Optional Host Dependency
Packet files may be:
- mounted from the host into containers
- or accessed through a predefined mounted directory only

For v1, prefer a clear mounted directory strategy.

---

## Folder Structure

```text
local-pcap-agent/
├─ AGENTS.md
├─ README.md
├─ docker-compose.yml
├─ .env.example
├─ apps/
│  ├─ frontend/
│  │  ├─ Dockerfile
│  │  ├─ requirements.txt
│  │  └─ app.py
│  └─ backend/
│     ├─ Dockerfile
│     ├─ requirements.txt
│     └─ app/
│        ├─ main.py
│        ├─ api/
│        ├─ services/
│        ├─ models/
│        ├─ prompts/
│        └─ config.py
├─ mcp/
│  └─ server/
│     ├─ Dockerfile
│     ├─ requirements.txt
│     ├─ server.py
│     ├─ tools/
│     │  ├─ files.py
│     │  ├─ metadata.py
│     │  ├─ tcp.py
│     │  ├─ http.py
│     │  ├─ tls.py
│     │  ├─ dns.py
│     │  └─ helpers.py
│     └─ tests/
├─ shared/
│  ├─ reports/
│  └─ cache/
├─ scripts/
│  ├─ run-dev.sh
│  ├─ test-ollama.sh
│  └─ sample-analysis.sh
└─ docs/
   ├─ architecture.md
   ├─ prompts.md
   ├─ tool-contracts.md
   └─ threat-model.md


Required User Flow
Step 1 - Ollama Configuration

The first screen in the frontend must be an Ollama configuration screen.

Required fields:

Ollama base URL

model name

Example defaults:

Ollama URL: http://host.docker.internal:11434

model: gpt-oss:20b

Required action

Button:

Test Ollama Connection

This should:

verify the Ollama server is reachable

verify the model exists or is callable

optionally run a tiny test prompt

show clear success/failure feedback

Only after success

The UI should then allow the user to continue into packet-analysis workflow.

This gating is important.

Step 2 - Packet Source Selection

The user should be able to provide:

a directory path

or a direct PCAP file path

The system should:

validate that the path exists inside allowed mounted locations

show discovered .pcap / .pcapng files

let the user choose the target file

Step 3 - Investigation Definition

The user enters free text describing what they want to investigate.

Examples:

"Find slow HTTP transactions"

"Check who sent the TCP resets"

"Find zero-window events"

"Show requests without responses"

"Look for TLS alert failures"

"Help me understand whether backend slowness is visible"

Optional toggles:

include HTTP

include TLS

include DNS

deep dive

limit packet extraction

privacy mode / redact payload-like data

Step 4 - Investigation Execution

The backend should:

confirm Ollama session config

validate the selected file

call MCP tools in stages

summarize evidence

produce a structured report

Analysis Strategy
Critical rule

Do not pass the raw PCAP directly into the LLM.

Required staged approach

Validate file

Read metadata

Get conversation summaries

Identify suspicious candidates

Drill into only relevant streams

Produce findings with evidence

Clearly separate:

confirmed facts

likely explanations

unknowns

MCP Server Responsibilities

The MCP server must run as a separate Docker service and expose safe packet-analysis tools.

MCP Tool Scope

The MCP server is responsible for wrapping:

file enumeration

path validation

metadata extraction

tcp conversation summaries

reset detection

retransmission detection

zero-window detection

http/tls/dns summaries

bounded stream-follow helpers

MCP Server Constraints

no arbitrary command execution

no unrestricted filesystem browsing

only allow known, bounded tool calls

enforce command timeouts

enforce output-size limits

Initial MCP Tool Set
File Tools
validate_pcap_path

Input:

path

Returns:

normalized path

type (file / directory)

validity

reason if rejected

list_pcaps

Input:

path

Returns:

files found

normalized accessible paths

metadata if cheap to compute

describe_capture

Input:

file_path

Returns:

output normalized from capinfos

Summary Tools
get_conversations

Input:

file_path

Returns:

TCP conversation summary

optionally UDP summary later

get_endpoints

Input:

file_path

Returns:

endpoint stats if implemented

TCP Tools
find_resets

Input:

file_path

Returns:

reset packets

timestamp

stream ID if resolvable

sender/receiver if resolvable

find_retransmissions

Input:

file_path

Returns:

retransmission indicators

find_zero_windows

Input:

file_path

Returns:

zero-window indicators

find_long_lived_connections

Input:

file_path

min_duration_seconds

Returns:

long-duration flows

follow_tcp_stream

Input:

file_path

stream_id

packet_limit

Returns:

bounded stream evidence

HTTP Tools
http_summary
requests_without_response
http_errors
TLS Tools
tls_handshake_summary
tls_alerts
DNS Tools
dns_summary
Generic Extraction
packet_slice

Input:

file_path

display_filter

limit

Returns:

bounded packets/fields only

Tool Design Principles
Safety

no general shell tool

fixed wrappers only

path validation required

output truncation required

Reliability

timeouts on every subprocess

structured errors

deterministic JSON output

graceful handling of broken captures

Portability

wrappers must avoid OS-specific assumptions where possible

any host path usage must be explicit and configurable

File Access Model

Because this app must be portable, file access must be simple and explicit.

Recommended v1 model

Mount a host directory into the containers, for example:

host: /Users/<user>/pcaps

container: /data/pcaps

The UI should instruct the user to work inside mounted directories.

Rules

only allow paths under configured allowed roots

normalize paths

reject traversal attempts

reject unmounted/unreachable paths with friendly error messages

Frontend Requirements

The frontend must be written in Python using Streamlit unless there is a compelling reason to choose another Python UI framework.

Frontend screens
1. Ollama Setup

Fields:

Ollama URL

Model name

Actions:

Test connection

Save session config

Display:

success/failure banner

model availability result

optional mini response test

2. Capture Selection

Fields:

directory path or file path

Actions:

scan path

select file

Display:

discovered PCAP files

file summary preview if available

3. Investigation Setup

Fields:

analysis goal text

analysis options

Actions:

start analysis

4. Results View

Display:

executive summary

findings

suspicious streams

evidence

Wireshark filters

raw tool snippets if needed

export button

Backend Responsibilities

The FastAPI backend should:

expose API for frontend

manage session state

store Ollama connection config per session

perform Ollama connectivity tests

call Ollama for reasoning

call MCP tools for packet analysis

aggregate and normalize evidence

expose final report

Suggested backend modules

services/ollama_service.py

services/mcp_client.py

services/analysis_service.py

services/session_service.py

services/report_service.py

Required Ollama Connectivity Features

This is a first-class feature, not an afterthought.

Required backend endpoint

POST /api/ollama/test

Request example:

{
  "base_url": "http://host.docker.internal:11434",
  "model": "gpt-oss:20b"
}

Expected behavior:

ping Ollama

verify model availability

run a tiny generation test if practical

return success/failure with reason

Required frontend behavior

Do not allow the investigation flow to proceed until Ollama test succeeds, unless there is an explicit developer override.

Nice-to-have

Display:

latency of test

model name resolved

short sample response

Suggested API Endpoints
POST /api/ollama/test

Test Ollama URL + model.

POST /api/files/scan

Input:

{
  "path": "/data/pcaps"
}
POST /api/analysis/start

Input:

{
  "ollama": {
    "base_url": "http://host.docker.internal:11434",
    "model": "gpt-oss:20b"
  },
  "file_path": "/data/pcaps/test.pcapng",
  "goal": "Find slow HTTP transactions and TCP resets",
  "options": {
    "include_http": true,
    "include_tls": true,
    "include_dns": false,
    "deep_dive": true
  }
}
GET /api/analysis/{analysis_id}

Returns progress and results.

GET /api/analysis/{analysis_id}/report

Returns markdown or JSON report.

Agent Behavior Contract

The agent should act like a careful packet analyst.

Must do

rely on tools

reason incrementally

show evidence

distinguish proof from interpretation

avoid overclaiming

Must not do

invent packet details

claim exact root cause without evidence

inspect giant outputs without narrowing first

use arbitrary commands

Required reasoning sequence

metadata

conversations

suspicious pattern detection

focused deep dive

final report

Output Format

The final output should include:

Summary

what is in the file

what stands out

likely issue areas

Findings

Each finding includes:

title

confidence

explanation

evidence

Wireshark display filter

Suspicious Streams

stream ID

endpoints

why flagged

Open Questions

what is not yet proven

Next Steps

concrete actions for the analyst

Example Result Object
{
  "summary": "The capture shows multiple long-lived TCP flows with resets and possible backend-side backpressure.",
  "findings": [
    {
      "title": "TCP resets sent by server-side endpoint",
      "confidence": "high",
      "explanation": "Several RST packets were observed from 10.1.2.20 toward 10.1.2.10.",
      "evidence": {
        "stream_ids": [12, 18],
        "packet_numbers": [4421, 9912],
        "filter": "tcp.flags.reset == 1"
      }
    }
  ]
}
Docker Compose Expectations

The docker-compose.yml should define at least:

frontend

backend

mcp-server

Notes

Ollama is external, not part of compose for v1

use shared network between services

mount configured PCAP directory into backend and mcp-server

optionally mount it into frontend only if needed for file browsing UX

Suggested volume concepts

host PCAP directory → /data/pcaps

reports directory → /data/reports

cache directory → /data/cache

Environment Variables

Suggested .env.example:

BACKEND_PORT=8000
FRONTEND_PORT=8501
LOG_LEVEL=INFO

DEFAULT_OLLAMA_BASE_URL=http://host.docker.internal:11434
DEFAULT_OLLAMA_MODEL=gpt-oss:20b

ALLOWED_PCAP_ROOTS=/data/pcaps
REPORTS_DIR=/data/reports
CACHE_DIR=/data/cache

MAX_PACKET_SLICE_RESULTS=200
MAX_STREAM_EXTRACT_CHARS=20000
ANALYSIS_TIMEOUT_SECONDS=120
OLLAMA_TEST_PROMPT=Reply with exactly: OLLAMA_OK
Testing Requirements
Unit Tests

path validation

ollama connectivity logic

subprocess wrapper behavior

output truncation

MCP tool JSON normalization

Integration Tests

frontend can call backend

backend can call MCP server

backend can test Ollama successfully

analysis works on a small sample capture

Manual Tests

wrong Ollama URL

valid Ollama URL but missing model

valid Ollama URL and valid model

scan mounted PCAP directory

run reset investigation

run slow-transaction investigation

Performance Guidelines

always start with summaries

never dump full capture decode into the model

limit stream extraction

limit packet slices

prefer small tool outputs

consider later caching by file hash

Security Requirements

no arbitrary shell access

strict path validation

no packet data sent outside local environment

configurable but bounded file access

redact or avoid payload-heavy dumps by default

keep logs safe and minimal by default

Phase Plan
Phase 1 - Portable Minimal Working System

Build:

Dockerized Streamlit frontend

Dockerized FastAPI backend

Dockerized Python MCP server

Ollama test workflow

path scan workflow

tools:

validate_pcap_path

list_pcaps

describe_capture

get_conversations

find_resets

first report output

README with portable setup instructions

Goal:
A user on any machine with Docker + Ollama can launch the stack, test the model connection, select a PCAP, and get first useful findings.

Phase 2 - Better TCP / HTTP Analysis

Add:

retransmissions

zero-window detection

long-lived flows

requests without response

HTTP summary

suspicious stream ranking

Phase 3 - TLS / DNS / Deep Dive

Add:

TLS alerts

TLS handshake summary

DNS summary

stream follow

packet slice tool

template investigations

Phase 4 - Quality and UX

Add:

export markdown/JSON

saved sessions

caching

compare two captures

richer evidence cards

Concrete Build Instructions for Claude Code

Start by implementing phase 1 exactly in this order:

Create repo structure

Create Docker Compose with:

frontend

backend

mcp-server

Build Python Streamlit frontend

Build FastAPI backend

Build Dockerized Python MCP server

Implement Ollama connectivity test end-to-end

Gate the rest of the UI until Ollama connectivity succeeds

Implement mounted PCAP directory scan flow

Implement these MCP tools first:

validate_pcap_path

list_pcaps

describe_capture

get_conversations

find_resets

Implement first analysis report screen

Add README with portable setup instructions for:

macOS

Linux

Docker Desktop users

Keep everything local-only

Implementation Preferences

Python everywhere

Streamlit for frontend

FastAPI for backend

Python MCP server

explicit subprocess wrappers for tshark/capinfos

typed JSON responses

simple maintainable code

practical over over-engineered

Suggested First Wrapped Commands

The first implementation will likely wrap commands equivalent to:

capinfos <file>

tshark -r <file> -q -z conv,tcp

tshark -r <file> -Y "tcp.flags.reset == 1" -T fields ...

Exact command flags may be refined during implementation, but wrappers must produce stable JSON.

Success Criteria for v1

v1 is successful if:

the full app stack runs in Docker

the user can configure Ollama from the UI

the user can test Ollama connectivity successfully

the user can select a local mounted capture

the system produces useful first-pass packet findings

findings include evidence and Wireshark filters

packet data stays local

Final Notes

This system should feel like:

portable

local-first

evidence-driven

practical for real troubleshooting

safe and bounded

When in doubt:

simplify

keep tools explicit

keep outputs bounded

optimize for analyst trust


And here’s the exact instruction I’d give Claude Code together with this file:

```text
Read AGENTS.md and scaffold phase 1 of the project.

Requirements:
- Python frontend with Streamlit
- Python backend with FastAPI
- Python MCP server in its own Docker container
- Docker Compose for frontend/backend/mcp-server
- Ollama is external and configurable from the UI
- UI must include:
  1. Ollama base URL input
  2. model name input
  3. Test Ollama Connection button
  4. only after success, allow packet-analysis workflow
- mounted PCAP directory support
- first MCP tools:
  - validate_pcap_path
  - list_pcaps
  - describe_capture
  - get_conversations
  - find_resets
- keep everything local-only
- create a clean README with portable setup instructions
- prefer maintainable code and clear JSON contracts


