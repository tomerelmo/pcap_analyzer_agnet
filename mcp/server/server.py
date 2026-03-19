import logging
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

# Import tool functions
from tools.files import validate_pcap_path, list_pcaps, describe_capture
from tools.helpers import packet_slice
from tools.metadata import (
    get_conversations,
    get_endpoints,
    get_protocol_hierarchy,
    get_io_stats,
)
from tools.tcp import (
    find_resets,
    find_retransmissions,
    find_zero_windows,
    find_duplicate_acks,
    find_long_lived_connections,
    get_tcp_summary,
    follow_tcp_stream,
)
from tools.http import (
    http_summary,
    http_errors,
    http_response_times,
    requests_without_response,
    http_top_uris,
)
from tools.tls import (
    tls_handshake_summary,
    tls_alerts,
    tls_certificate_info,
)
from tools.dns import (
    dns_summary,
    dns_failed_queries,
    dns_suspicious_patterns,
    dns_response_times,
)
from tools.security import (
    detect_port_scan,
    detect_beaconing,
    find_cleartext_credentials,
    detect_data_exfiltration,
    get_expert_info,
)
from tools.performance import (
    get_service_response_times,
    get_throughput_analysis,
    find_slow_connections,
    get_connection_stats,
)
from tools.network import (
    dhcp_summary,
    arp_analysis,
    icmp_analysis,
    smb_summary,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PCAP MCP Server",
    description="Bounded packet-analysis tools for the PCAP Analyzer system",
    version="2.0.0",
)


# --------------------------------------------------------------------------
# Request schemas
# --------------------------------------------------------------------------

class ValidatePcapPathRequest(BaseModel):
    path: str


class ListPcapsRequest(BaseModel):
    path: str


class DescribeCaptureRequest(BaseModel):
    file_path: str


class GetConversationsRequest(BaseModel):
    file_path: str
    proto: str = "tcp"


class GetEndpointsRequest(BaseModel):
    file_path: str
    proto: str = "tcp"


class GetProtocolHierarchyRequest(BaseModel):
    file_path: str


class GetIoStatsRequest(BaseModel):
    file_path: str
    interval: float = 1.0
    display_filter: Optional[str] = None


class GetExpertInfoRequest(BaseModel):
    file_path: str
    min_severity: str = "warn"


class FindResetsRequest(BaseModel):
    file_path: str


class FindRetransmissionsRequest(BaseModel):
    file_path: str


class FindZeroWindowsRequest(BaseModel):
    file_path: str


class FindDuplicateAcksRequest(BaseModel):
    file_path: str


class FindLongLivedConnectionsRequest(BaseModel):
    file_path: str
    min_duration_seconds: float = 30.0


class GetTcpSummaryRequest(BaseModel):
    file_path: str


class FollowTcpStreamRequest(BaseModel):
    file_path: str
    stream_index: int
    max_chars: Optional[int] = None


class HttpSummaryRequest(BaseModel):
    file_path: str


class HttpErrorsRequest(BaseModel):
    file_path: str


class HttpResponseTimesRequest(BaseModel):
    file_path: str


class RequestsWithoutResponseRequest(BaseModel):
    file_path: str


class HttpTopUrisRequest(BaseModel):
    file_path: str
    limit: int = 20


class TlsHandshakeSummaryRequest(BaseModel):
    file_path: str


class TlsAlertsRequest(BaseModel):
    file_path: str


class TlsCertificateInfoRequest(BaseModel):
    file_path: str


class DnsSummaryRequest(BaseModel):
    file_path: str


class DnsFailedQueriesRequest(BaseModel):
    file_path: str


class DnsSuspiciousPatternsRequest(BaseModel):
    file_path: str


class DnsResponseTimesRequest(BaseModel):
    file_path: str


class DetectPortScanRequest(BaseModel):
    file_path: str


class DetectBeaconingRequest(BaseModel):
    file_path: str


class FindCleartextCredentialsRequest(BaseModel):
    file_path: str


class DetectDataExfiltrationRequest(BaseModel):
    file_path: str


class GetServiceResponseTimesRequest(BaseModel):
    file_path: str
    protocol: str = "http"


class GetThroughputAnalysisRequest(BaseModel):
    file_path: str
    interval_seconds: float = 1.0


class FindSlowConnectionsRequest(BaseModel):
    file_path: str
    threshold_ms: float = 200.0


class GetConnectionStatsRequest(BaseModel):
    file_path: str


class DhcpSummaryRequest(BaseModel):
    file_path: str


class ArpAnalysisRequest(BaseModel):
    file_path: str


class IcmpAnalysisRequest(BaseModel):
    file_path: str


class SmbSummaryRequest(BaseModel):
    file_path: str


class PacketSliceRequest(BaseModel):
    file_path: str
    display_filter: Optional[str] = None
    fields: Optional[list[str]] = None
    limit: Optional[int] = None


# --------------------------------------------------------------------------
# GET /tools — tool registry
# --------------------------------------------------------------------------

TOOL_REGISTRY = [
    {
        "name": "validate_pcap_path",
        "description": "Validate that a path is within allowed roots and exists.",
        "parameters": {"path": "string"},
    },
    {
        "name": "list_pcaps",
        "description": "List .pcap and .pcapng files at a path.",
        "parameters": {"path": "string"},
    },
    {
        "name": "describe_capture",
        "description": "Run capinfos on a PCAP file and return structured metadata.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "get_conversations",
        "description": "Get conversation statistics (TCP, UDP, IP, IPv6, Ethernet).",
        "parameters": {"file_path": "string", "proto": "string (default: tcp)"},
    },
    {
        "name": "get_endpoints",
        "description": "Get endpoint statistics sorted by total bytes.",
        "parameters": {"file_path": "string", "proto": "string (default: tcp)"},
    },
    {
        "name": "get_protocol_hierarchy",
        "description": "Get protocol hierarchy statistics.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "get_io_stats",
        "description": "Get IO statistics over time intervals.",
        "parameters": {
            "file_path": "string",
            "interval": "float (default: 1.0)",
            "display_filter": "string (optional)",
        },
    },
    {
        "name": "get_expert_info",
        "description": "Get tshark expert info items grouped by severity and protocol.",
        "parameters": {
            "file_path": "string",
            "min_severity": "string: chat|note|warn|error (default: warn)",
        },
    },
    {
        "name": "find_resets",
        "description": "Find TCP RST packets.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "find_retransmissions",
        "description": "Find TCP retransmissions and fast retransmissions.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "find_zero_windows",
        "description": "Find TCP zero-window and window-full events.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "find_duplicate_acks",
        "description": "Find TCP duplicate ACK events.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "find_long_lived_connections",
        "description": "Find TCP connections longer than a minimum duration.",
        "parameters": {
            "file_path": "string",
            "min_duration_seconds": "float (default: 30.0)",
        },
    },
    {
        "name": "get_tcp_summary",
        "description": "Comprehensive TCP health check with health score.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "follow_tcp_stream",
        "description": "Follow a TCP stream and return ASCII content.",
        "parameters": {
            "file_path": "string",
            "stream_index": "integer",
            "max_chars": "integer (optional)",
        },
    },
    {
        "name": "http_summary",
        "description": "Summarize HTTP traffic: methods, status codes, hosts, user agents.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "http_errors",
        "description": "Extract HTTP 4xx/5xx error responses.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "http_response_times",
        "description": "Analyze HTTP response times using two-pass analysis.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "requests_without_response",
        "description": "Find HTTP requests with no corresponding response.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "http_top_uris",
        "description": "Find the most frequently requested HTTP URIs.",
        "parameters": {"file_path": "string", "limit": "integer (default: 20)"},
    },
    {
        "name": "tls_handshake_summary",
        "description": "Summarize TLS handshakes: versions, cipher suites, SNI.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "tls_alerts",
        "description": "Extract TLS alert messages with level and type.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "tls_certificate_info",
        "description": "Extract TLS certificate validity information.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "dns_summary",
        "description": "Summarize DNS traffic: query types, top domains, NXDOMAIN count.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "dns_failed_queries",
        "description": "Find DNS queries that received error responses.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "dns_suspicious_patterns",
        "description": "Detect suspicious DNS patterns: DGA, tunneling, zone transfers.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "dns_response_times",
        "description": "Analyze DNS response times via SRT statistics.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "detect_port_scan",
        "description": "Detect TCP SYN port scans and ICMP sweeps.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "detect_beaconing",
        "description": "Detect potential C2 beaconing via connection interval analysis.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "find_cleartext_credentials",
        "description": "Find cleartext credentials in FTP, HTTP Basic Auth, SMTP, POP3.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "detect_data_exfiltration",
        "description": "Detect potential data exfiltration: large uploads, DNS/ICMP tunneling.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "get_service_response_times",
        "description": "Get service response time statistics via SRT.",
        "parameters": {
            "file_path": "string",
            "protocol": "string: http|dns|smb|smb2|dcerpc (default: http)",
        },
    },
    {
        "name": "get_throughput_analysis",
        "description": "Analyze throughput over time: peak, average, bursty periods.",
        "parameters": {
            "file_path": "string",
            "interval_seconds": "float (default: 1.0)",
        },
    },
    {
        "name": "find_slow_connections",
        "description": "Find TCP connections with slow handshakes (high initial RTT).",
        "parameters": {
            "file_path": "string",
            "threshold_ms": "float (default: 200.0)",
        },
    },
    {
        "name": "get_connection_stats",
        "description": "Overall connection health: SYN/SYN-ACK/FIN/RST counts, success rate.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "dhcp_summary",
        "description": "Summarize DHCP traffic and detect rogue DHCP servers.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "arp_analysis",
        "description": "Analyze ARP: gratuitous ARP, IP conflicts, flooding.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "icmp_analysis",
        "description": "Analyze ICMP: types, unreachables, large payloads, tunneling.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "smb_summary",
        "description": "Summarize SMB/SMB2 traffic: operations, auth failures, shares.",
        "parameters": {"file_path": "string"},
    },
    {
        "name": "packet_slice",
        "description": "Extract a slice of packets with optional filter and field selection.",
        "parameters": {
            "file_path": "string",
            "display_filter": "string (optional)",
            "fields": "list[string] (optional)",
            "limit": "integer (optional)",
        },
    },
]


@app.get("/tools")
def list_tools():
    """List all available tools with their parameter schemas."""
    return {
        "tools": TOOL_REGISTRY,
        "count": len(TOOL_REGISTRY),
    }


# --------------------------------------------------------------------------
# File tools
# --------------------------------------------------------------------------

@app.post("/tools/validate_pcap_path")
def tool_validate_pcap_path(request: ValidatePcapPathRequest):
    """Validate a path: checks it's within allowed roots and exists."""
    try:
        return validate_pcap_path(request.path)
    except Exception as e:
        logger.exception("Error in validate_pcap_path")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/list_pcaps")
def tool_list_pcaps(request: ListPcapsRequest):
    """List .pcap and .pcapng files at a path."""
    try:
        return list_pcaps(request.path)
    except Exception as e:
        logger.exception("Error in list_pcaps")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/describe_capture")
def tool_describe_capture(request: DescribeCaptureRequest):
    """Run capinfos on a PCAP file and return structured metadata."""
    try:
        return describe_capture(request.file_path)
    except Exception as e:
        logger.exception("Error in describe_capture")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/packet_slice")
def tool_packet_slice(request: PacketSliceRequest):
    """Extract a slice of packets with optional filter and field selection."""
    try:
        return packet_slice(
            file_path=request.file_path,
            display_filter=request.display_filter,
            fields=request.fields,
            limit=request.limit,
        )
    except Exception as e:
        logger.exception("Error in packet_slice")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Metadata tools
# --------------------------------------------------------------------------

@app.post("/tools/get_conversations")
def tool_get_conversations(request: GetConversationsRequest):
    """Get conversation statistics for a PCAP file."""
    try:
        return get_conversations(request.file_path, proto=request.proto)
    except Exception as e:
        logger.exception("Error in get_conversations")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_endpoints")
def tool_get_endpoints(request: GetEndpointsRequest):
    """Get endpoint statistics for a PCAP file."""
    try:
        return get_endpoints(request.file_path, proto=request.proto)
    except Exception as e:
        logger.exception("Error in get_endpoints")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_protocol_hierarchy")
def tool_get_protocol_hierarchy(request: GetProtocolHierarchyRequest):
    """Get protocol hierarchy statistics."""
    try:
        return get_protocol_hierarchy(request.file_path)
    except Exception as e:
        logger.exception("Error in get_protocol_hierarchy")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_io_stats")
def tool_get_io_stats(request: GetIoStatsRequest):
    """Get IO statistics over time intervals."""
    try:
        return get_io_stats(
            request.file_path,
            interval=request.interval,
            display_filter=request.display_filter,
        )
    except Exception as e:
        logger.exception("Error in get_io_stats")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# TCP tools
# --------------------------------------------------------------------------

@app.post("/tools/find_resets")
def tool_find_resets(request: FindResetsRequest):
    """Find TCP RST packets in a PCAP file."""
    try:
        return find_resets(request.file_path)
    except Exception as e:
        logger.exception("Error in find_resets")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_retransmissions")
def tool_find_retransmissions(request: FindRetransmissionsRequest):
    """Find TCP retransmissions and fast retransmissions."""
    try:
        return find_retransmissions(request.file_path)
    except Exception as e:
        logger.exception("Error in find_retransmissions")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_zero_windows")
def tool_find_zero_windows(request: FindZeroWindowsRequest):
    """Find TCP zero-window and window-full events."""
    try:
        return find_zero_windows(request.file_path)
    except Exception as e:
        logger.exception("Error in find_zero_windows")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_duplicate_acks")
def tool_find_duplicate_acks(request: FindDuplicateAcksRequest):
    """Find TCP duplicate ACK events."""
    try:
        return find_duplicate_acks(request.file_path)
    except Exception as e:
        logger.exception("Error in find_duplicate_acks")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_long_lived_connections")
def tool_find_long_lived_connections(request: FindLongLivedConnectionsRequest):
    """Find TCP connections lasting longer than a minimum duration."""
    try:
        return find_long_lived_connections(
            request.file_path,
            min_duration_seconds=request.min_duration_seconds,
        )
    except Exception as e:
        logger.exception("Error in find_long_lived_connections")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_tcp_summary")
def tool_get_tcp_summary(request: GetTcpSummaryRequest):
    """Comprehensive TCP health check."""
    try:
        return get_tcp_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in get_tcp_summary")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/follow_tcp_stream")
def tool_follow_tcp_stream(request: FollowTcpStreamRequest):
    """Follow a TCP stream and return ASCII content."""
    try:
        return follow_tcp_stream(
            request.file_path,
            stream_index=request.stream_index,
            max_chars=request.max_chars,
        )
    except Exception as e:
        logger.exception("Error in follow_tcp_stream")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# HTTP tools
# --------------------------------------------------------------------------

@app.post("/tools/http_summary")
def tool_http_summary(request: HttpSummaryRequest):
    """Summarize HTTP traffic."""
    try:
        return http_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in http_summary")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/http_errors")
def tool_http_errors(request: HttpErrorsRequest):
    """Extract HTTP 4xx/5xx error responses."""
    try:
        return http_errors(request.file_path)
    except Exception as e:
        logger.exception("Error in http_errors")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/http_response_times")
def tool_http_response_times(request: HttpResponseTimesRequest):
    """Analyze HTTP response times."""
    try:
        return http_response_times(request.file_path)
    except Exception as e:
        logger.exception("Error in http_response_times")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/requests_without_response")
def tool_requests_without_response(request: RequestsWithoutResponseRequest):
    """Find HTTP requests with no corresponding response."""
    try:
        return requests_without_response(request.file_path)
    except Exception as e:
        logger.exception("Error in requests_without_response")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/http_top_uris")
def tool_http_top_uris(request: HttpTopUrisRequest):
    """Find the most frequently requested HTTP URIs."""
    try:
        return http_top_uris(request.file_path, limit=request.limit)
    except Exception as e:
        logger.exception("Error in http_top_uris")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# TLS tools
# --------------------------------------------------------------------------

@app.post("/tools/tls_handshake_summary")
def tool_tls_handshake_summary(request: TlsHandshakeSummaryRequest):
    """Summarize TLS handshakes."""
    try:
        return tls_handshake_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in tls_handshake_summary")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/tls_alerts")
def tool_tls_alerts(request: TlsAlertsRequest):
    """Extract TLS alert messages."""
    try:
        return tls_alerts(request.file_path)
    except Exception as e:
        logger.exception("Error in tls_alerts")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/tls_certificate_info")
def tool_tls_certificate_info(request: TlsCertificateInfoRequest):
    """Extract TLS certificate validity information."""
    try:
        return tls_certificate_info(request.file_path)
    except Exception as e:
        logger.exception("Error in tls_certificate_info")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# DNS tools
# --------------------------------------------------------------------------

@app.post("/tools/dns_summary")
def tool_dns_summary(request: DnsSummaryRequest):
    """Summarize DNS traffic."""
    try:
        return dns_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in dns_summary")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/dns_failed_queries")
def tool_dns_failed_queries(request: DnsFailedQueriesRequest):
    """Find DNS queries that received error responses."""
    try:
        return dns_failed_queries(request.file_path)
    except Exception as e:
        logger.exception("Error in dns_failed_queries")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/dns_suspicious_patterns")
def tool_dns_suspicious_patterns(request: DnsSuspiciousPatternsRequest):
    """Detect suspicious DNS patterns."""
    try:
        return dns_suspicious_patterns(request.file_path)
    except Exception as e:
        logger.exception("Error in dns_suspicious_patterns")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/dns_response_times")
def tool_dns_response_times(request: DnsResponseTimesRequest):
    """Analyze DNS response times."""
    try:
        return dns_response_times(request.file_path)
    except Exception as e:
        logger.exception("Error in dns_response_times")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Security tools
# --------------------------------------------------------------------------

@app.post("/tools/detect_port_scan")
def tool_detect_port_scan(request: DetectPortScanRequest):
    """Detect TCP SYN port scans and ICMP sweeps."""
    try:
        return detect_port_scan(request.file_path)
    except Exception as e:
        logger.exception("Error in detect_port_scan")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/detect_beaconing")
def tool_detect_beaconing(request: DetectBeaconingRequest):
    """Detect potential C2 beaconing via connection interval analysis."""
    try:
        return detect_beaconing(request.file_path)
    except Exception as e:
        logger.exception("Error in detect_beaconing")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_cleartext_credentials")
def tool_find_cleartext_credentials(request: FindCleartextCredentialsRequest):
    """Find cleartext credentials in FTP, HTTP Basic Auth, SMTP, POP3."""
    try:
        return find_cleartext_credentials(request.file_path)
    except Exception as e:
        logger.exception("Error in find_cleartext_credentials")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/detect_data_exfiltration")
def tool_detect_data_exfiltration(request: DetectDataExfiltrationRequest):
    """Detect potential data exfiltration patterns."""
    try:
        return detect_data_exfiltration(request.file_path)
    except Exception as e:
        logger.exception("Error in detect_data_exfiltration")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_expert_info")
def tool_get_expert_info(request: GetExpertInfoRequest):
    """Get tshark expert info items grouped by severity and protocol."""
    try:
        return get_expert_info(request.file_path, min_severity=request.min_severity)
    except Exception as e:
        logger.exception("Error in get_expert_info")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Performance tools
# --------------------------------------------------------------------------

@app.post("/tools/get_service_response_times")
def tool_get_service_response_times(request: GetServiceResponseTimesRequest):
    """Get service response time statistics via SRT."""
    try:
        return get_service_response_times(request.file_path, protocol=request.protocol)
    except Exception as e:
        logger.exception("Error in get_service_response_times")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_throughput_analysis")
def tool_get_throughput_analysis(request: GetThroughputAnalysisRequest):
    """Analyze throughput over time."""
    try:
        return get_throughput_analysis(
            request.file_path,
            interval_seconds=request.interval_seconds,
        )
    except Exception as e:
        logger.exception("Error in get_throughput_analysis")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/find_slow_connections")
def tool_find_slow_connections(request: FindSlowConnectionsRequest):
    """Find TCP connections with slow handshakes."""
    try:
        return find_slow_connections(
            request.file_path,
            threshold_ms=request.threshold_ms,
        )
    except Exception as e:
        logger.exception("Error in find_slow_connections")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/get_connection_stats")
def tool_get_connection_stats(request: GetConnectionStatsRequest):
    """Overall connection health statistics."""
    try:
        return get_connection_stats(request.file_path)
    except Exception as e:
        logger.exception("Error in get_connection_stats")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Network tools
# --------------------------------------------------------------------------

@app.post("/tools/dhcp_summary")
def tool_dhcp_summary(request: DhcpSummaryRequest):
    """Summarize DHCP traffic and detect rogue DHCP servers."""
    try:
        return dhcp_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in dhcp_summary")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/arp_analysis")
def tool_arp_analysis(request: ArpAnalysisRequest):
    """Analyze ARP: gratuitous ARP, IP conflicts, flooding."""
    try:
        return arp_analysis(request.file_path)
    except Exception as e:
        logger.exception("Error in arp_analysis")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/icmp_analysis")
def tool_icmp_analysis(request: IcmpAnalysisRequest):
    """Analyze ICMP: types, unreachables, large payloads, tunneling."""
    try:
        return icmp_analysis(request.file_path)
    except Exception as e:
        logger.exception("Error in icmp_analysis")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tools/smb_summary")
def tool_smb_summary(request: SmbSummaryRequest):
    """Summarize SMB/SMB2 traffic."""
    try:
        return smb_summary(request.file_path)
    except Exception as e:
        logger.exception("Error in smb_summary")
        raise HTTPException(status_code=500, detail=str(e))


# --------------------------------------------------------------------------
# Health check
# --------------------------------------------------------------------------

@app.get("/health")
def health_check():
    tool_names = [t["name"] for t in TOOL_REGISTRY]
    return {"status": "ok", "tools": tool_names, "tool_count": len(tool_names)}
