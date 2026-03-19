FROM python:3.12-slim

# Install tshark and capinfos (from wireshark-common) non-interactively
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends tshark wireshark-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server and tools
COPY server.py .
COPY tools/ ./tools/

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
