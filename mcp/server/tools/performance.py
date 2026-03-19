import logging
import re
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)

SUPPORTED_SRT_PROTOCOLS = {"http", "dns", "smb", "smb2", "dcerpc"}


# ---------------------------------------------------------------------------
# get_service_response_times
# ---------------------------------------------------------------------------

def get_service_response_times(file_path: str, protocol: str = "http") -> dict:
    """
    Get service response time statistics using tshark SRT.

    Args:
        file_path: Path to PCAP file.
        protocol: One of http, dns, smb, smb2, dcerpc.

    Returns:
        {file, protocol, avg_ms, max_ms, min_ms, total_calls, by_procedure}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "protocol": protocol,
            "avg_ms": 0,
            "max_ms": 0,
            "min_ms": 0,
            "total_calls": 0,
            "by_procedure": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    if protocol not in SUPPORTED_SRT_PROTOCOLS:
        return {
            "file": normalized,
            "protocol": protocol,
            "avg_ms": 0,
            "max_ms": 0,
            "min_ms": 0,
            "total_calls": 0,
            "by_procedure": [],
            "error": (
                f"Unsupported protocol '{protocol}'. "
                f"Must be one of: {', '.join(sorted(SUPPORTED_SRT_PROTOCOLS))}"
            ),
        }

    stdout = run_tshark_stat(normalized, f"srt,{protocol}", timeout=60)
    avg_ms, max_ms, min_ms, total_calls, by_procedure = _parse_srt_output(stdout)

    return {
        "file": normalized,
        "protocol": protocol,
        "avg_ms": avg_ms,
        "max_ms": max_ms,
        "min_ms": min_ms,
        "total_calls": total_calls,
        "by_procedure": by_procedure,
        "raw_stats": stdout.strip(),
    }


def _parse_srt_output(output: str) -> tuple[float, float, float, int, list]:
    """Parse tshark SRT output into timing stats."""
    avg_ms = 0.0
    max_ms = 0.0
    min_ms = 0.0
    total_calls = 0
    by_procedure = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Overall summary line
        m = re.search(
            r"(?:Calls|Total):\s*(\d+).*?Min:\s*([\d.]+)s.*?Max:\s*([\d.]+)s.*?Avg:\s*([\d.]+)s",
            stripped, re.IGNORECASE,
        )
        if m:
            total_calls = int(m.group(1))
            min_ms = round(float(m.group(2)) * 1000, 2)
            max_ms = round(float(m.group(3)) * 1000, 2)
            avg_ms = round(float(m.group(4)) * 1000, 2)
            continue

        # Per-procedure lines: Name  count  min  max  avg
        m2 = re.match(
            r"(.+?)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
            stripped,
        )
        if m2:
            try:
                name = m2.group(1).strip()
                count = int(m2.group(2))
                p_min = round(float(m2.group(3)) * 1000, 2)
                p_max = round(float(m2.group(4)) * 1000, 2)
                p_avg = round(float(m2.group(5)) * 1000, 2)
                by_procedure.append({
                    "name": name,
                    "count": count,
                    "min_ms": p_min,
                    "max_ms": p_max,
                    "avg_ms": p_avg,
                })
                if total_calls == 0:
                    total_calls += count
            except (ValueError, IndexError):
                pass

    if by_procedure and total_calls > 0 and avg_ms == 0:
        # Compute aggregate from procedures
        total_weighted = sum(p["avg_ms"] * p["count"] for p in by_procedure)
        avg_ms = round(total_weighted / total_calls, 2)
        min_ms = min((p["min_ms"] for p in by_procedure), default=0)
        max_ms = max((p["max_ms"] for p in by_procedure), default=0)

    return avg_ms, max_ms, min_ms, total_calls, by_procedure


# ---------------------------------------------------------------------------
# get_throughput_analysis
# ---------------------------------------------------------------------------

def get_throughput_analysis(
    file_path: str,
    interval_seconds: float = 1.0,
) -> dict:
    """
    Analyze throughput over time to find bursty and quiet periods.

    Returns:
        {file, interval_seconds, avg_bps, peak_bps, peak_interval,
         buckets, bursty_periods, utilization_timeline}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "interval_seconds": interval_seconds,
            "avg_bps": 0,
            "peak_bps": 0,
            "peak_interval": None,
            "buckets": [],
            "bursty_periods": [],
            "utilization_timeline": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Use metadata.get_io_stats for bucket data
    from tools.metadata import get_io_stats
    io_result = get_io_stats(normalized, interval=interval_seconds)

    buckets = io_result.get("buckets", [])
    avg_bps = io_result.get("avg_bps", 0)
    peak_bps = io_result.get("peak_bps", 0)

    # Find peak interval
    peak_interval = None
    if buckets:
        peak_bucket = max(buckets, key=lambda b: b.get("bits_per_second", 0))
        peak_interval = {
            "start": peak_bucket.get("interval_start"),
            "end": peak_bucket.get("interval_end"),
            "bps": peak_bucket.get("bits_per_second"),
        }

    # Identify bursty (> 2x avg) and quiet (< 0.1x avg) periods
    bursty_periods = []
    quiet_periods = []

    if avg_bps > 0:
        for bucket in buckets:
            bps = bucket.get("bits_per_second", 0)
            if bps > 2 * avg_bps:
                bursty_periods.append({
                    "start": bucket.get("interval_start"),
                    "end": bucket.get("interval_end"),
                    "bps": bps,
                    "ratio_to_avg": round(bps / avg_bps, 2),
                })
            elif bps < 0.1 * avg_bps and bucket.get("frames", 0) > 0:
                quiet_periods.append({
                    "start": bucket.get("interval_start"),
                    "end": bucket.get("interval_end"),
                    "bps": bps,
                })

    # Build utilization timeline (compact representation)
    utilization_timeline = [
        {
            "t": b.get("interval_start"),
            "bps": b.get("bits_per_second", 0),
            "frames": b.get("frames", 0),
        }
        for b in buckets
    ]

    return {
        "file": normalized,
        "interval_seconds": interval_seconds,
        "avg_bps": avg_bps,
        "peak_bps": peak_bps,
        "peak_interval": peak_interval,
        "buckets": buckets,
        "bursty_periods": bursty_periods,
        "utilization_timeline": utilization_timeline,
    }


# ---------------------------------------------------------------------------
# find_slow_connections
# ---------------------------------------------------------------------------

def find_slow_connections(
    file_path: str,
    threshold_ms: float = 200.0,
) -> dict:
    """
    Find TCP connections with slow handshakes (high initial RTT).

    Uses two-pass analysis to get tcp.analysis.initial_rtt.

    Returns:
        {file, slow_handshakes, avg_handshake_ms, max_handshake_ms,
         threshold_ms, slow_count}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "slow_handshakes": [],
            "avg_handshake_ms": 0,
            "max_handshake_ms": 0,
            "threshold_ms": threshold_ms,
            "slow_count": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "tcp.flags.ack",
        "tcp.analysis.initial_rtt",
    ]

    rows = run_tshark_fields(
        normalized,
        "tcp.analysis.initial_rtt",
        fields,
        timeout=30,
        two_pass=True,
    )

    slow_handshakes = []
    all_rtts_ms = []

    for row in rows:
        rtt_str = row.get("tcp.analysis.initial_rtt", "").strip()
        if not rtt_str:
            continue

        try:
            rtt_s = float(rtt_str)
            rtt_ms = round(rtt_s * 1000, 3)
            all_rtts_ms.append(rtt_ms)

            if rtt_ms > threshold_ms:
                slow_handshakes.append({
                    "frame_number": row.get("frame.number", ""),
                    "time_relative": row.get("frame.time_relative", ""),
                    "ip_src": row.get("ip.src", ""),
                    "ip_dst": row.get("ip.dst", ""),
                    "tcp_stream": row.get("tcp.stream", ""),
                    "initial_rtt_ms": rtt_ms,
                })
        except (ValueError, TypeError):
            continue

    slow_handshakes.sort(key=lambda x: x["initial_rtt_ms"], reverse=True)

    avg_ms = round(sum(all_rtts_ms) / len(all_rtts_ms), 3) if all_rtts_ms else 0.0
    max_ms = max(all_rtts_ms) if all_rtts_ms else 0.0

    return {
        "file": normalized,
        "slow_handshakes": slow_handshakes,
        "avg_handshake_ms": avg_ms,
        "max_handshake_ms": max_ms,
        "threshold_ms": threshold_ms,
        "slow_count": len(slow_handshakes),
    }


# ---------------------------------------------------------------------------
# get_connection_stats
# ---------------------------------------------------------------------------

def get_connection_stats(file_path: str) -> dict:
    """
    Overall connection health statistics: packet counts, flag ratios, etc.

    Returns:
        {file, total_packets, tcp_conversations, udp_flows, syn_count, synack_count,
         fin_count, rst_count, connection_success_rate_pct, refused_connections}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_packets": 0,
            "tcp_conversations": 0,
            "udp_flows": 0,
            "syn_count": 0,
            "synack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "connection_success_rate_pct": 0.0,
            "refused_connections": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # SYN (no ACK)
    syn_rows = run_tshark_fields(
        normalized,
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        ["frame.number", "ip.src", "ip.dst", "tcp.dstport"],
        timeout=30,
    )
    syn_count = len(syn_rows)

    # SYN-ACK
    synack_rows = run_tshark_fields(
        normalized,
        "tcp.flags.syn == 1 && tcp.flags.ack == 1",
        ["frame.number"],
        timeout=30,
    )
    synack_count = len(synack_rows)

    # FIN
    fin_rows = run_tshark_fields(
        normalized,
        "tcp.flags.fin == 1",
        ["frame.number"],
        timeout=30,
    )
    fin_count = len(fin_rows)

    # RST
    rst_rows = run_tshark_fields(
        normalized,
        "tcp.flags.reset == 1",
        ["frame.number"],
        timeout=30,
    )
    rst_count = len(rst_rows)

    # Connection success rate
    success_rate = (
        round(synack_count / syn_count * 100, 2) if syn_count > 0 else 0.0
    )

    # Find refused connections: SYN followed by RST from destination
    # Detect via SYN targets where we have RST but no SYN-ACK for that flow
    syn_targets: set[tuple[str, str, str]] = set()
    for row in syn_rows:
        src = row.get("ip.src", "").strip()
        dst = row.get("ip.dst", "").strip()
        dport = row.get("tcp.dstport", "").strip()
        if src and dst and dport:
            syn_targets.add((src, dst, dport))

    # Refused = RST from server with no prior SYN-ACK (heuristic: RST to dstport)
    rst_refusal_fields = ["frame.number", "ip.src", "ip.dst", "tcp.srcport"]
    rst_detail_rows = run_tshark_fields(
        normalized,
        "tcp.flags.reset == 1 && tcp.flags.ack == 0",
        rst_refusal_fields,
        timeout=30,
    )

    refused_connections = []
    seen_refused: set[tuple[str, str, str]] = set()
    for row in rst_detail_rows:
        rst_src = row.get("ip.src", "").strip()
        rst_dst = row.get("ip.dst", "").strip()
        rst_sport = row.get("tcp.srcport", "").strip()

        # If we see RST from a server (i.e., RST source == SYN dst, sport == SYN dport)
        key = (rst_dst, rst_src, rst_sport)
        if key in syn_targets and key not in seen_refused:
            seen_refused.add(key)
            refused_connections.append({
                "client": rst_dst,
                "server": rst_src,
                "port": rst_sport,
            })

    # Get conversation counts from metadata
    from tools.metadata import get_conversations
    tcp_conv = get_conversations(normalized, proto="tcp")
    udp_conv = get_conversations(normalized, proto="udp")

    # Estimate total packets from describe_capture (or sum conversations)
    from tools.files import describe_capture
    cap_info = describe_capture(normalized)
    total_packets_str = cap_info.get("info", {}).get("Number of packets", "0")
    try:
        total_packets = int(total_packets_str.replace(",", "").strip())
    except (ValueError, TypeError):
        total_packets = sum(
            c.get("frames_total", 0) for c in tcp_conv.get("conversations", [])
        )

    return {
        "file": normalized,
        "total_packets": total_packets,
        "tcp_conversations": tcp_conv.get("count", 0),
        "udp_flows": udp_conv.get("count", 0),
        "syn_count": syn_count,
        "synack_count": synack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "connection_success_rate_pct": success_rate,
        "refused_connections": refused_connections[:50],
    }
