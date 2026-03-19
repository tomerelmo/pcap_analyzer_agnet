import logging
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_command, run_tshark_fields, run_tshark_stat, get_max_results, get_max_stream_chars

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# find_resets
# ---------------------------------------------------------------------------

def find_resets(file_path: str) -> dict:
    """
    Find TCP RST packets in a capture file.

    Returns:
        {file, resets, count, truncated}
    Each reset: {frame_number, time_relative, ip_src, ip_dst, tcp_srcport, tcp_dstport, tcp_stream}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "resets": [],
            "count": 0,
            "truncated": False,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
    ]

    rows = run_tshark_fields(
        normalized,
        "tcp.flags.reset==1",
        fields,
        timeout=30,
    )

    max_results = get_max_results()
    truncated = len(rows) >= max_results

    resets = []
    for row in rows:
        resets.append({
            "frame_number": row.get("frame.number", ""),
            "time_relative": row.get("frame.time_relative", ""),
            "ip_src": row.get("ip.src", ""),
            "tcp_srcport": row.get("tcp.srcport", ""),
            "ip_dst": row.get("ip.dst", ""),
            "tcp_dstport": row.get("tcp.dstport", ""),
            "tcp_stream": row.get("tcp.stream", ""),
        })

    return {
        "file": normalized,
        "resets": resets,
        "count": len(resets),
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# find_retransmissions
# ---------------------------------------------------------------------------

def find_retransmissions(file_path: str) -> dict:
    """
    Find TCP retransmissions and fast retransmissions.

    Returns:
        {file, retransmissions, fast_retransmissions, total_count, by_stream}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "retransmissions": [],
            "fast_retransmissions": [],
            "total_count": 0,
            "by_stream": {},
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "tcp.seq",
    ]

    retrans_rows = run_tshark_fields(
        normalized,
        "tcp.analysis.retransmission",
        fields,
        timeout=30,
    )

    fast_rows = run_tshark_fields(
        normalized,
        "tcp.analysis.fast_retransmission",
        fields,
        timeout=30,
    )

    def rows_to_list(rows: list[dict]) -> list[dict]:
        result = []
        for row in rows:
            result.append({
                "frame_number": row.get("frame.number", ""),
                "time_relative": row.get("frame.time_relative", ""),
                "ip_src": row.get("ip.src", ""),
                "tcp_srcport": row.get("tcp.srcport", ""),
                "ip_dst": row.get("ip.dst", ""),
                "tcp_dstport": row.get("tcp.dstport", ""),
                "tcp_stream": row.get("tcp.stream", ""),
                "tcp_seq": row.get("tcp.seq", ""),
            })
        return result

    retransmissions = rows_to_list(retrans_rows)
    fast_retransmissions = rows_to_list(fast_rows)

    by_stream: dict[str, int] = defaultdict(int)
    for item in retransmissions + fast_retransmissions:
        stream = item.get("tcp_stream", "unknown")
        by_stream[stream] += 1

    return {
        "file": normalized,
        "retransmissions": retransmissions,
        "fast_retransmissions": fast_retransmissions,
        "total_count": len(retransmissions) + len(fast_retransmissions),
        "by_stream": dict(by_stream),
    }


# ---------------------------------------------------------------------------
# find_zero_windows
# ---------------------------------------------------------------------------

def find_zero_windows(file_path: str) -> dict:
    """
    Find TCP zero-window and window-full events.

    Returns:
        {file, zero_windows, window_full_events, count, affected_streams}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "zero_windows": [],
            "window_full_events": [],
            "count": 0,
            "affected_streams": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.stream",
        "tcp.window_size",
    ]

    zw_rows = run_tshark_fields(
        normalized,
        "tcp.analysis.zero_window",
        fields,
        timeout=30,
    )

    wf_rows = run_tshark_fields(
        normalized,
        "tcp.analysis.window_full",
        fields,
        timeout=30,
    )

    def rows_to_list(rows: list[dict]) -> list[dict]:
        result = []
        for row in rows:
            result.append({
                "frame_number": row.get("frame.number", ""),
                "time_relative": row.get("frame.time_relative", ""),
                "ip_src": row.get("ip.src", ""),
                "tcp_srcport": row.get("tcp.srcport", ""),
                "ip_dst": row.get("ip.dst", ""),
                "tcp_dstport": row.get("tcp.dstport", ""),
                "tcp_stream": row.get("tcp.stream", ""),
                "tcp_window_size": row.get("tcp.window_size", ""),
            })
        return result

    zero_windows = rows_to_list(zw_rows)
    window_full_events = rows_to_list(wf_rows)

    affected_streams = list(
        {item["tcp_stream"] for item in zero_windows + window_full_events if item["tcp_stream"]}
    )

    return {
        "file": normalized,
        "zero_windows": zero_windows,
        "window_full_events": window_full_events,
        "count": len(zero_windows) + len(window_full_events),
        "affected_streams": affected_streams,
    }


# ---------------------------------------------------------------------------
# find_duplicate_acks
# ---------------------------------------------------------------------------

def find_duplicate_acks(file_path: str) -> dict:
    """
    Find TCP duplicate ACK events.

    Returns:
        {file, duplicate_acks, count, by_stream}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "duplicate_acks": [],
            "count": 0,
            "by_stream": {},
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "tcp.ack",
    ]

    rows = run_tshark_fields(
        normalized,
        "tcp.analysis.duplicate_ack",
        fields,
        timeout=30,
    )

    duplicate_acks = []
    by_stream: dict[str, int] = defaultdict(int)

    for row in rows:
        stream = row.get("tcp.stream", "unknown")
        by_stream[stream] += 1
        duplicate_acks.append({
            "frame_number": row.get("frame.number", ""),
            "time_relative": row.get("frame.time_relative", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "tcp_stream": stream,
            "tcp_ack": row.get("tcp.ack", ""),
        })

    return {
        "file": normalized,
        "duplicate_acks": duplicate_acks,
        "count": len(duplicate_acks),
        "by_stream": dict(by_stream),
    }


# ---------------------------------------------------------------------------
# find_long_lived_connections
# ---------------------------------------------------------------------------

def find_long_lived_connections(
    file_path: str,
    min_duration_seconds: float = 30.0,
) -> dict:
    """
    Find TCP connections lasting longer than min_duration_seconds.

    Returns:
        {file, connections, count, threshold_seconds}
    """
    from tools.metadata import get_conversations

    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "connections": [],
            "count": 0,
            "threshold_seconds": min_duration_seconds,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    conv_result = get_conversations(normalized, proto="tcp")

    if "error" in conv_result:
        return {
            "file": normalized,
            "connections": [],
            "count": 0,
            "threshold_seconds": min_duration_seconds,
            "error": conv_result["error"],
        }

    long_lived = []
    for conv in conv_result.get("conversations", []):
        duration = conv.get("duration", 0)
        try:
            duration_f = float(duration)
        except (ValueError, TypeError):
            continue

        if duration_f >= min_duration_seconds:
            bytes_a_to_b = conv.get("bytes_a_to_b", 0)
            bytes_b_to_a = conv.get("bytes_b_to_a", 0)
            total_bytes = conv.get("bytes_total", bytes_a_to_b + bytes_b_to_a)

            # Direction ratio: outbound / inbound (avoid division by zero)
            direction_ratio = (
                round(bytes_a_to_b / bytes_b_to_a, 3)
                if bytes_b_to_a > 0
                else float("inf") if bytes_a_to_b > 0 else 1.0
            )

            long_lived.append({
                "src": conv.get("src", ""),
                "dst": conv.get("dst", ""),
                "duration_seconds": duration_f,
                "bytes_total": total_bytes,
                "bytes_a_to_b": bytes_a_to_b,
                "bytes_b_to_a": bytes_b_to_a,
                "direction_ratio": direction_ratio,
                "frames_total": conv.get("frames_total", 0),
                "bps": conv.get("bps", 0),
            })

    long_lived.sort(key=lambda c: c["duration_seconds"], reverse=True)

    return {
        "file": normalized,
        "connections": long_lived,
        "count": len(long_lived),
        "threshold_seconds": min_duration_seconds,
    }


# ---------------------------------------------------------------------------
# get_tcp_summary
# ---------------------------------------------------------------------------

def get_tcp_summary(file_path: str) -> dict:
    """
    Comprehensive TCP health check combining multiple analyses.

    Returns:
        {file, health_score, total_tcp_conversations, reset_count, retransmission_count,
         zero_window_count, dup_ack_count, retransmission_rate_pct, issues}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "health_score": "unknown",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Gather all data
    from tools.metadata import get_conversations
    conv_result = get_conversations(normalized, proto="tcp")
    reset_result = find_resets(normalized)
    retrans_result = find_retransmissions(normalized)
    zw_result = find_zero_windows(normalized)
    dup_ack_result = find_duplicate_acks(normalized)

    total_tcp_conversations = conv_result.get("count", 0)
    reset_count = reset_result.get("count", 0)
    retransmission_count = retrans_result.get("total_count", 0)
    zero_window_count = len(zw_result.get("zero_windows", []))
    dup_ack_count = dup_ack_result.get("count", 0)

    # Estimate total TCP packets from conversations
    total_tcp_packets = sum(
        c.get("frames_total", 0) for c in conv_result.get("conversations", [])
    )

    retransmission_rate_pct = (
        round(retransmission_count / total_tcp_packets * 100, 2)
        if total_tcp_packets > 0
        else 0.0
    )
    reset_rate_pct = (
        round(reset_count / total_tcp_packets * 100, 2)
        if total_tcp_packets > 0
        else 0.0
    )

    issues = []
    if retransmission_rate_pct > 5:
        issues.append(f"High retransmission rate: {retransmission_rate_pct:.1f}% of TCP packets")
    if reset_count > 10:
        issues.append(f"Elevated RST count: {reset_count} resets detected")
    if zero_window_count > 0:
        issues.append(f"TCP zero-window events detected: {zero_window_count}")
    if dup_ack_count > 20:
        issues.append(f"High duplicate ACK count: {dup_ack_count}")

    # Health scoring
    if len(issues) == 0:
        health_score = "good"
    elif len(issues) <= 2 and retransmission_rate_pct <= 10:
        health_score = "degraded"
    else:
        health_score = "poor"

    return {
        "file": normalized,
        "health_score": health_score,
        "total_tcp_conversations": total_tcp_conversations,
        "total_tcp_packets": total_tcp_packets,
        "reset_count": reset_count,
        "retransmission_count": retransmission_count,
        "zero_window_count": zero_window_count,
        "dup_ack_count": dup_ack_count,
        "retransmission_rate_pct": retransmission_rate_pct,
        "reset_rate_pct": reset_rate_pct,
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# follow_tcp_stream
# ---------------------------------------------------------------------------

def follow_tcp_stream(
    file_path: str,
    stream_index: int,
    max_chars: int | None = None,
) -> dict:
    """
    Follow a TCP stream and return ASCII content.

    Returns:
        {file, stream_index, content, truncated, char_count}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "stream_index": stream_index,
            "content": "",
            "truncated": False,
            "char_count": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    limit = max_chars if max_chars is not None else get_max_stream_chars()

    stdout, stderr, returncode = run_command(
        [
            "tshark",
            "-r", normalized,
            "-q",
            "-z", f"follow,tcp,ascii,{stream_index}",
        ],
        timeout=30,
    )

    if returncode not in (0, 1) and not stdout:
        return {
            "file": normalized,
            "stream_index": stream_index,
            "content": "",
            "truncated": False,
            "char_count": 0,
            "error": f"tshark exited with code {returncode}: {stderr.strip()}",
        }

    content = stdout
    truncated = len(content) > limit
    if truncated:
        content = content[:limit]

    return {
        "file": normalized,
        "stream_index": stream_index,
        "content": content,
        "truncated": truncated,
        "char_count": len(content),
    }
