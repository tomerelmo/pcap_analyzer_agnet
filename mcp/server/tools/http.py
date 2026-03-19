import logging
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# http_summary
# ---------------------------------------------------------------------------

def http_summary(file_path: str) -> dict:
    """
    Summarize HTTP traffic in a capture file.

    Returns:
        {file, total_requests, total_responses, by_method, by_status_code,
         top_hosts, unique_user_agents, raw_stats}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_requests": 0,
            "total_responses": 0,
            "by_method": {},
            "by_status_code": {},
            "top_hosts": [],
            "unique_user_agents": [],
            "raw_stats": "",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Get raw http,tree stats
    raw_stats = run_tshark_stat(normalized, "http,tree", timeout=60)

    # Extract request fields
    req_fields = [
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.request.uri",
        "http.host",
        "http.user_agent",
    ]
    req_rows = run_tshark_fields(
        normalized,
        "http.request",
        req_fields,
        timeout=30,
    )

    # Extract response fields
    resp_fields = [
        "ip.src",
        "ip.dst",
        "http.response.code",
    ]
    resp_rows = run_tshark_fields(
        normalized,
        "http.response",
        resp_fields,
        timeout=30,
    )

    by_method: dict[str, int] = defaultdict(int)
    host_counts: dict[str, int] = defaultdict(int)
    user_agents: set[str] = set()

    for row in req_rows:
        method = row.get("http.request.method", "").strip()
        if method:
            by_method[method] += 1
        host = row.get("http.host", "").strip()
        if host:
            host_counts[host] += 1
        ua = row.get("http.user_agent", "").strip()
        if ua:
            user_agents.add(ua)

    by_status_code: dict[str, int] = defaultdict(int)
    for row in resp_rows:
        code = row.get("http.response.code", "").strip()
        if code:
            by_status_code[code] += 1

    top_hosts = sorted(
        [{"host": h, "count": c} for h, c in host_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:20]

    return {
        "file": normalized,
        "total_requests": len(req_rows),
        "total_responses": len(resp_rows),
        "by_method": dict(by_method),
        "by_status_code": dict(by_status_code),
        "top_hosts": top_hosts,
        "unique_user_agents": list(user_agents)[:50],
        "raw_stats": raw_stats.strip(),
    }


# ---------------------------------------------------------------------------
# http_errors
# ---------------------------------------------------------------------------

def http_errors(file_path: str) -> dict:
    """
    Extract HTTP 4xx/5xx error responses.

    Returns:
        {file, errors, count, by_code}
    Each error: {frame_number, time_relative, ip_src, ip_dst, response_code}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "errors": [],
            "count": 0,
            "by_code": {},
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "http.response.code",
        "http.request.uri",
    ]

    rows = run_tshark_fields(
        normalized,
        "http.response.code >= 400",
        fields,
        timeout=30,
    )

    errors = []
    by_code: dict[str, int] = defaultdict(int)

    for row in rows:
        code = row.get("http.response.code", "").strip()
        if code:
            by_code[code] += 1
        errors.append({
            "frame_number": row.get("frame.number", ""),
            "time_relative": row.get("frame.time_relative", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "response_code": code,
            "request_uri": row.get("http.request.uri", ""),
        })

    return {
        "file": normalized,
        "errors": errors,
        "count": len(errors),
        "by_code": dict(by_code),
    }


# ---------------------------------------------------------------------------
# http_response_times
# ---------------------------------------------------------------------------

def http_response_times(file_path: str) -> dict:
    """
    Analyze HTTP response times using tshark http.time field (two-pass).

    Returns:
        {file, avg_ms, max_ms, min_ms, slow_requests, total_measured}
    Each slow request (>1s): {frame_number, uri, response_code, time_ms}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "avg_ms": 0,
            "max_ms": 0,
            "min_ms": 0,
            "slow_requests": [],
            "total_measured": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Two-pass analysis for http.time
    fields = [
        "frame.number",
        "http.request.uri",
        "http.response.code",
        "http.time",
    ]

    rows = run_tshark_fields(
        normalized,
        "http.time",
        fields,
        timeout=30,
        two_pass=True,
    )

    times_ms = []
    slow_requests = []

    for row in rows:
        raw_time = row.get("http.time", "").strip()
        if not raw_time:
            continue
        try:
            time_s = float(raw_time)
            time_ms = round(time_s * 1000, 2)
            times_ms.append(time_ms)

            if time_ms > 1000:
                slow_requests.append({
                    "frame_number": row.get("frame.number", ""),
                    "uri": row.get("http.request.uri", ""),
                    "response_code": row.get("http.response.code", ""),
                    "time_ms": time_ms,
                })
        except (ValueError, TypeError):
            continue

    if not times_ms:
        return {
            "file": normalized,
            "avg_ms": 0,
            "max_ms": 0,
            "min_ms": 0,
            "slow_requests": [],
            "total_measured": 0,
        }

    slow_requests.sort(key=lambda r: r["time_ms"], reverse=True)

    return {
        "file": normalized,
        "avg_ms": round(sum(times_ms) / len(times_ms), 2),
        "max_ms": max(times_ms),
        "min_ms": min(times_ms),
        "slow_requests": slow_requests[:50],
        "total_measured": len(times_ms),
    }


# ---------------------------------------------------------------------------
# requests_without_response
# ---------------------------------------------------------------------------

def requests_without_response(file_path: str) -> dict:
    """
    Find HTTP requests that have no corresponding response.

    Uses two-pass analysis with http.response_in field.

    Returns:
        {file, unanswered_requests, count}
    Each: {frame_number, method, uri, ip_src, ip_dst}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "unanswered_requests": [],
            "count": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "http.request.method",
        "http.request.uri",
        "http.response_in",
    ]

    rows = run_tshark_fields(
        normalized,
        "http.request",
        fields,
        timeout=30,
        two_pass=True,
    )

    unanswered = []
    for row in rows:
        response_in = row.get("http.response_in", "").strip()
        if not response_in:
            unanswered.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": row.get("ip.src", ""),
                "ip_dst": row.get("ip.dst", ""),
                "method": row.get("http.request.method", ""),
                "uri": row.get("http.request.uri", ""),
            })

    return {
        "file": normalized,
        "unanswered_requests": unanswered,
        "count": len(unanswered),
    }


# ---------------------------------------------------------------------------
# http_top_uris
# ---------------------------------------------------------------------------

def http_top_uris(file_path: str, limit: int = 20) -> dict:
    """
    Find the most frequently requested URIs.

    Returns:
        {file, top_uris, total_requests}
    Each entry: {uri, count}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "top_uris": [],
            "total_requests": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = ["http.request.uri"]

    rows = run_tshark_fields(
        normalized,
        "http.request",
        fields,
        timeout=30,
    )

    uri_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        uri = row.get("http.request.uri", "").strip()
        if uri:
            uri_counts[uri] += 1

    top_uris = sorted(
        [{"uri": u, "count": c} for u, c in uri_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:limit]

    return {
        "file": normalized,
        "top_uris": top_uris,
        "total_requests": len(rows),
    }
