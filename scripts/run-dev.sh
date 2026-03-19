#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "==> Setting up PCAP Analyzer development environment"

# Copy .env.example to .env if not present
cp -n .env.example .env 2>/dev/null || true
echo "==> .env file ready"

# Create required directories
mkdir -p sample_pcaps shared/reports shared/cache
echo "==> Directories ready (sample_pcaps, shared/reports, shared/cache)"

echo ""
echo "==> Starting services with docker compose..."
echo "    Frontend:  http://localhost:8501"
echo "    Backend:   http://localhost:8000"
echo "    MCP Docs:  http://localhost:8001/docs  (not exposed externally)"
echo ""

docker compose up --build
