import logging
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

MCP_TIMEOUT = 90.0


async def _call_tool(tool_name: str, params: dict) -> dict:
    """Generic MCP tool caller via HTTP POST."""
    url = f"{settings.mcp_server_url}/tools/{tool_name}"
    try:
        async with httpx.AsyncClient(timeout=MCP_TIMEOUT) as client:
            resp = await client.post(url, json=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise RuntimeError(
            f"Cannot connect to MCP server at {settings.mcp_server_url}. "
            "Is the mcp-server container running?"
        )
    except httpx.TimeoutException:
        raise RuntimeError(f"MCP tool '{tool_name}' timed out")
    except httpx.HTTPStatusError as e:
        try:
            detail = e.response.json().get("detail", e.response.text)
        except Exception:
            detail = e.response.text
        raise RuntimeError(f"MCP tool '{tool_name}' returned HTTP {e.response.status_code}: {detail}")
    except Exception as e:
        raise RuntimeError(f"MCP tool '{tool_name}' error: {e}")


async def _get_tools() -> dict:
    """Fetch the tool registry from the MCP server."""
    url = f"{settings.mcp_server_url}/tools"
    try:
        async with httpx.AsyncClient(timeout=MCP_TIMEOUT) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch tool registry: {e}")


# --------------------------------------------------------------------------
# File tools
# --------------------------------------------------------------------------

async def validate_pcap_path(path: str) -> dict:
    return await _call_tool("validate_pcap_path", {"path": path})


async def list_pcaps(path: str) -> dict:
    return await _call_tool("list_pcaps", {"path": path})


async def describe_capture(file_path: str) -> dict:
    return await _call_tool("describe_capture", {"file_path": file_path})


async def packet_slice(
    file_path: str,
    display_filter: str | None = None,
    fields: list[str] | None = None,
    limit: int | None = None,
) -> dict:
    params: dict = {"file_path": file_path}
    if display_filter is not None:
        params["display_filter"] = display_filter
    if fields is not None:
        params["fields"] = fields
    if limit is not None:
        params["limit"] = limit
    return await _call_tool("packet_slice", params)


# --------------------------------------------------------------------------
# Metadata tools
# --------------------------------------------------------------------------

async def get_conversations(file_path: str, proto: str = "tcp") -> dict:
    return await _call_tool("get_conversations", {"file_path": file_path, "proto": proto})


async def get_endpoints(file_path: str, proto: str = "tcp") -> dict:
    return await _call_tool("get_endpoints", {"file_path": file_path, "proto": proto})


async def get_protocol_hierarchy(file_path: str) -> dict:
    return await _call_tool("get_protocol_hierarchy", {"file_path": file_path})


async def get_io_stats(
    file_path: str,
    interval: float = 1.0,
    display_filter: str | None = None,
) -> dict:
    params: dict = {"file_path": file_path, "interval": interval}
    if display_filter is not None:
        params["display_filter"] = display_filter
    return await _call_tool("get_io_stats", params)


# --------------------------------------------------------------------------
# TCP tools
# --------------------------------------------------------------------------

async def find_resets(file_path: str) -> dict:
    return await _call_tool("find_resets", {"file_path": file_path})


async def find_retransmissions(file_path: str) -> dict:
    return await _call_tool("find_retransmissions", {"file_path": file_path})


async def find_zero_windows(file_path: str) -> dict:
    return await _call_tool("find_zero_windows", {"file_path": file_path})


async def find_duplicate_acks(file_path: str) -> dict:
    return await _call_tool("find_duplicate_acks", {"file_path": file_path})


async def find_long_lived_connections(
    file_path: str,
    min_duration_seconds: float = 30.0,
) -> dict:
    return await _call_tool(
        "find_long_lived_connections",
        {"file_path": file_path, "min_duration_seconds": min_duration_seconds},
    )


async def get_tcp_summary(file_path: str) -> dict:
    return await _call_tool("get_tcp_summary", {"file_path": file_path})


async def follow_tcp_stream(
    file_path: str,
    stream_index: int,
    max_chars: int | None = None,
) -> dict:
    params: dict = {"file_path": file_path, "stream_index": stream_index}
    if max_chars is not None:
        params["max_chars"] = max_chars
    return await _call_tool("follow_tcp_stream", params)


# --------------------------------------------------------------------------
# HTTP tools
# --------------------------------------------------------------------------

async def http_summary(file_path: str) -> dict:
    return await _call_tool("http_summary", {"file_path": file_path})


async def http_errors(file_path: str) -> dict:
    return await _call_tool("http_errors", {"file_path": file_path})


async def http_response_times(file_path: str) -> dict:
    return await _call_tool("http_response_times", {"file_path": file_path})


async def requests_without_response(file_path: str) -> dict:
    return await _call_tool("requests_without_response", {"file_path": file_path})


async def http_top_uris(file_path: str, limit: int = 20) -> dict:
    return await _call_tool("http_top_uris", {"file_path": file_path, "limit": limit})


# --------------------------------------------------------------------------
# TLS tools
# --------------------------------------------------------------------------

async def tls_handshake_summary(file_path: str) -> dict:
    return await _call_tool("tls_handshake_summary", {"file_path": file_path})


async def tls_alerts(file_path: str) -> dict:
    return await _call_tool("tls_alerts", {"file_path": file_path})


async def tls_certificate_info(file_path: str) -> dict:
    return await _call_tool("tls_certificate_info", {"file_path": file_path})


# --------------------------------------------------------------------------
# DNS tools
# --------------------------------------------------------------------------

async def dns_summary(file_path: str) -> dict:
    return await _call_tool("dns_summary", {"file_path": file_path})


async def dns_failed_queries(file_path: str) -> dict:
    return await _call_tool("dns_failed_queries", {"file_path": file_path})


async def dns_suspicious_patterns(file_path: str) -> dict:
    return await _call_tool("dns_suspicious_patterns", {"file_path": file_path})


async def dns_response_times(file_path: str) -> dict:
    return await _call_tool("dns_response_times", {"file_path": file_path})


# --------------------------------------------------------------------------
# Security tools
# --------------------------------------------------------------------------

async def detect_port_scan(file_path: str) -> dict:
    return await _call_tool("detect_port_scan", {"file_path": file_path})


async def detect_beaconing(file_path: str) -> dict:
    return await _call_tool("detect_beaconing", {"file_path": file_path})


async def find_cleartext_credentials(file_path: str) -> dict:
    return await _call_tool("find_cleartext_credentials", {"file_path": file_path})


async def detect_data_exfiltration(file_path: str) -> dict:
    return await _call_tool("detect_data_exfiltration", {"file_path": file_path})


async def get_expert_info(file_path: str, min_severity: str = "warn") -> dict:
    return await _call_tool(
        "get_expert_info",
        {"file_path": file_path, "min_severity": min_severity},
    )


# --------------------------------------------------------------------------
# Performance tools
# --------------------------------------------------------------------------

async def get_service_response_times(file_path: str, protocol: str = "http") -> dict:
    return await _call_tool(
        "get_service_response_times",
        {"file_path": file_path, "protocol": protocol},
    )


async def get_throughput_analysis(
    file_path: str,
    interval_seconds: float = 1.0,
) -> dict:
    return await _call_tool(
        "get_throughput_analysis",
        {"file_path": file_path, "interval_seconds": interval_seconds},
    )


async def find_slow_connections(
    file_path: str,
    threshold_ms: float = 200.0,
) -> dict:
    return await _call_tool(
        "find_slow_connections",
        {"file_path": file_path, "threshold_ms": threshold_ms},
    )


async def get_connection_stats(file_path: str) -> dict:
    return await _call_tool("get_connection_stats", {"file_path": file_path})


# --------------------------------------------------------------------------
# Network tools
# --------------------------------------------------------------------------

async def dhcp_summary(file_path: str) -> dict:
    return await _call_tool("dhcp_summary", {"file_path": file_path})


async def arp_analysis(file_path: str) -> dict:
    return await _call_tool("arp_analysis", {"file_path": file_path})


async def icmp_analysis(file_path: str) -> dict:
    return await _call_tool("icmp_analysis", {"file_path": file_path})


async def smb_summary(file_path: str) -> dict:
    return await _call_tool("smb_summary", {"file_path": file_path})
