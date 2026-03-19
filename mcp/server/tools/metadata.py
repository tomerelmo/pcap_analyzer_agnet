import logging
import re
from tools.files import validate_pcap_path
from tools.helpers import run_command, run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)

MAX_CONVERSATIONS = 100
MAX_ENDPOINTS = 100


# ---------------------------------------------------------------------------
# get_conversations
# ---------------------------------------------------------------------------

def get_conversations(file_path: str, proto: str = "tcp") -> dict:
    """
    Run tshark conversation stats for a protocol and return parsed results.

    Args:
        file_path: Path to PCAP file.
        proto: Protocol - one of tcp, udp, ip, ipv6, eth.

    Returns:
        {proto, conversations, count, truncated}
    Each conversation: {src, dst, frames_total, bytes_total, frames_a_to_b,
                        bytes_a_to_b, frames_b_to_a, bytes_b_to_a, duration, bps}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "proto": proto,
            "conversations": [],
            "count": 0,
            "truncated": False,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    valid_protos = {"tcp", "udp", "ip", "ipv6", "eth"}
    if proto not in valid_protos:
        return {
            "file": normalized,
            "proto": proto,
            "conversations": [],
            "count": 0,
            "truncated": False,
            "error": f"Invalid proto '{proto}'. Must be one of: {', '.join(sorted(valid_protos))}",
        }

    stdout = run_tshark_stat(normalized, f"conv,{proto}", timeout=60)
    conversations = _parse_conversation_table(stdout, proto)

    # Sort by bytes_total descending
    conversations.sort(key=lambda c: c.get("bytes_total", 0), reverse=True)

    truncated = len(conversations) > MAX_CONVERSATIONS
    limited = conversations[:MAX_CONVERSATIONS]

    return {
        "file": normalized,
        "proto": proto,
        "conversations": limited,
        "count": len(conversations),
        "truncated": truncated,
    }


def _parse_conversation_table(output: str, proto: str) -> list[dict]:
    """Parse tshark -z conv,<proto> output into structured dicts."""
    conversations = []
    lines = output.splitlines()
    in_table = False

    for line in lines:
        stripped = line.strip()

        # Detect table header section
        if re.search(r"conversations", stripped, re.IGNORECASE):
            in_table = True
            continue

        if not in_table:
            continue

        # Skip decorators and column headers
        if not stripped or stripped.startswith("=") or stripped.startswith("-"):
            continue
        if re.search(r"Address\s+[AB]|Port\s+[AB]|Filter:", stripped, re.IGNORECASE):
            continue
        if re.search(r"\|.*<-.*->.*\|", stripped):
            continue
        if re.search(r"Packets\s+Bytes\s+Packets\s+Bytes", stripped, re.IGNORECASE):
            continue

        conv = _parse_conv_line(stripped, proto)
        if conv:
            conversations.append(conv)

    return conversations


def _parse_conv_line(line: str, proto: str) -> dict | None:
    """Parse a single conversation table data line."""
    parts = line.split()

    # Need at minimum: addr_a [port_a] addr_b [port_b] + numeric fields
    min_parts = 10 if proto in ("tcp", "udp") else 8
    if len(parts) < min_parts:
        return None

    def looks_like_addr(s: str) -> bool:
        return bool(
            re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s)
            or re.match(r"^[0-9a-fA-F:]{5,17}$", s)  # MAC
            or re.match(r"^[a-fA-F0-9:]+$", s)        # IPv6 fragment
            or re.match(r"^[a-zA-Z0-9.\-]+$", s)
        )

    try:
        if proto in ("tcp", "udp"):
            if not looks_like_addr(parts[0]):
                return None
            src = f"{parts[0]}:{parts[1]}"
            dst = f"{parts[2]}:{parts[3]}"
            nums = parts[4:]
        else:
            if not looks_like_addr(parts[0]):
                return None
            src = parts[0]
            dst = parts[1]
            nums = parts[2:]

        if len(nums) < 6:
            return None

        frames_a_to_b = _safe_int(nums[0])
        bytes_a_to_b = _safe_int(nums[1])
        frames_b_to_a = _safe_int(nums[2])
        bytes_b_to_a = _safe_int(nums[3])
        frames_total = _safe_int(nums[4])
        bytes_total = _safe_int(nums[5])
        duration = _safe_float(nums[7]) if len(nums) > 7 else 0.0

        # bps: total bits / duration
        bps = (bytes_total * 8 / duration) if duration > 0 else 0.0

        return {
            "src": src,
            "dst": dst,
            "frames_a_to_b": frames_a_to_b,
            "bytes_a_to_b": bytes_a_to_b,
            "frames_b_to_a": frames_b_to_a,
            "bytes_b_to_a": bytes_b_to_a,
            "frames_total": frames_total,
            "bytes_total": bytes_total,
            "duration": duration,
            "bps": round(bps, 2),
        }
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# get_endpoints
# ---------------------------------------------------------------------------

def get_endpoints(file_path: str, proto: str = "tcp") -> dict:
    """
    Run tshark endpoint stats for a protocol and return parsed results.

    Args:
        file_path: Path to PCAP file.
        proto: Protocol - one of tcp, udp, ip, ipv6, eth.

    Returns:
        {proto, endpoints, count}
    Each endpoint: {address, frames_tx, bytes_tx, frames_rx, bytes_rx, total_frames, total_bytes}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "proto": proto,
            "endpoints": [],
            "count": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    valid_protos = {"tcp", "udp", "ip", "ipv6", "eth"}
    if proto not in valid_protos:
        return {
            "file": normalized,
            "proto": proto,
            "endpoints": [],
            "count": 0,
            "error": f"Invalid proto '{proto}'. Must be one of: {', '.join(sorted(valid_protos))}",
        }

    stdout = run_tshark_stat(normalized, f"endpoints,{proto}", timeout=60)
    endpoints = _parse_endpoint_table(stdout)

    endpoints.sort(key=lambda e: e.get("total_bytes", 0), reverse=True)
    limited = endpoints[:MAX_ENDPOINTS]

    return {
        "file": normalized,
        "proto": proto,
        "endpoints": limited,
        "count": len(endpoints),
    }


def _parse_endpoint_table(output: str) -> list[dict]:
    """Parse tshark -z endpoints output."""
    endpoints = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if re.search(r"endpoints", stripped, re.IGNORECASE):
            in_table = True
            continue

        if not in_table:
            continue

        if stripped.startswith("=") or stripped.startswith("-"):
            continue
        if re.search(r"Address|Filter:", stripped, re.IGNORECASE):
            continue
        if re.search(r"Packets\s+Bytes", stripped, re.IGNORECASE):
            continue

        ep = _parse_endpoint_line(stripped)
        if ep:
            endpoints.append(ep)

    return endpoints


def _parse_endpoint_line(line: str) -> dict | None:
    """Parse a single endpoint table line."""
    parts = line.split()
    if len(parts) < 5:
        return None

    try:
        address = parts[0]
        frames_tx = _safe_int(parts[1])
        bytes_tx = _safe_int(parts[2])
        frames_rx = _safe_int(parts[3])
        bytes_rx = _safe_int(parts[4])
        total_frames = frames_tx + frames_rx
        total_bytes = bytes_tx + bytes_rx

        return {
            "address": address,
            "frames_tx": frames_tx,
            "bytes_tx": bytes_tx,
            "frames_rx": frames_rx,
            "bytes_rx": bytes_rx,
            "total_frames": total_frames,
            "total_bytes": total_bytes,
        }
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# get_protocol_hierarchy
# ---------------------------------------------------------------------------

def get_protocol_hierarchy(file_path: str) -> dict:
    """
    Get protocol hierarchy statistics via tshark -z io,phs.

    Returns:
        {hierarchy: list, summary: str}
    Each entry: {protocol, frames, bytes, percent_frames, percent_bytes, level}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "hierarchy": [],
            "summary": "",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    stdout = run_tshark_stat(normalized, "io,phs", timeout=60)

    hierarchy = _parse_protocol_hierarchy(stdout)

    return {
        "file": normalized,
        "hierarchy": hierarchy,
        "summary": stdout.strip(),
    }


def _parse_protocol_hierarchy(output: str) -> list[dict]:
    """Parse tshark protocol hierarchy statistics output."""
    entries = []
    in_section = False

    for line in output.splitlines():
        # Detect start of phs output
        if "Protocol Hierarchy Statistics" in line:
            in_section = True
            continue

        if not in_section:
            continue

        stripped = line.rstrip()
        if not stripped or stripped.startswith("="):
            continue
        if re.search(r"Filter:|frames:|bytes:", stripped, re.IGNORECASE) and "%" not in stripped:
            continue

        entry = _parse_phs_line(stripped)
        if entry:
            entries.append(entry)

    return entries


def _parse_phs_line(line: str) -> dict | None:
    """Parse a single line of protocol hierarchy output."""
    # Lines look like:
    #   eth                              frames:1000 bytes:60000
    #     ip                             frames:900 bytes:55000
    stripped = line.rstrip()
    indent = len(stripped) - len(stripped.lstrip())
    level = indent // 2

    # Match: <proto_name> frames:<n> bytes:<n>
    m = re.search(
        r"(\S+)\s+frames:(\d+)\s+bytes:(\d+)",
        stripped,
    )
    if not m:
        return None

    protocol = m.group(1)
    frames = int(m.group(2))
    bytes_val = int(m.group(3))

    # percent fields come from parent context — we skip computing them here
    return {
        "protocol": protocol,
        "frames": frames,
        "bytes": bytes_val,
        "level": level,
    }


# ---------------------------------------------------------------------------
# get_io_stats
# ---------------------------------------------------------------------------

def get_io_stats(
    file_path: str,
    interval: float = 1.0,
    display_filter: str | None = None,
) -> dict:
    """
    Get IO statistics over time intervals.

    Args:
        file_path: Path to PCAP file.
        interval: Time bucket size in seconds.
        display_filter: Optional display filter.

    Returns:
        {interval, buckets, peak_bps, avg_bps, total_frames, total_bytes}
    Each bucket: {interval_start, interval_end, frames, bytes, bits_per_second}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "interval": interval,
            "buckets": [],
            "peak_bps": 0,
            "avg_bps": 0,
            "total_frames": 0,
            "total_bytes": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    stat_name = f"io,stat,{interval}"
    stdout = run_tshark_stat(normalized, stat_name, display_filter=display_filter, timeout=60)

    buckets = _parse_io_stats(stdout, interval)

    total_frames = sum(b["frames"] for b in buckets)
    total_bytes = sum(b["bytes"] for b in buckets)
    bps_list = [b["bits_per_second"] for b in buckets if b["bits_per_second"] > 0]
    peak_bps = max(bps_list) if bps_list else 0
    avg_bps = sum(bps_list) / len(bps_list) if bps_list else 0

    return {
        "file": normalized,
        "interval": interval,
        "buckets": buckets,
        "peak_bps": round(peak_bps, 2),
        "avg_bps": round(avg_bps, 2),
        "total_frames": total_frames,
        "total_bytes": total_bytes,
    }


def _parse_io_stats(output: str, interval: float) -> list[dict]:
    """Parse tshark -z io,stat output into buckets."""
    buckets = []
    in_table = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if "IO Statistics" in stripped:
            in_table = True
            continue

        if not in_table:
            continue

        if stripped.startswith("=") or stripped.startswith("-"):
            continue

        if re.search(r"Duration|Interval|Frames|Bytes", stripped, re.IGNORECASE):
            continue

        # Lines look like: | 0.000 <> 1.000 | 42 | 1234 |
        m = re.match(
            r"\|?\s*([\d.]+)\s*<>\s*([\d.]+)\s*\|?\s*(\d+)\s*\|?\s*(\d+)",
            stripped,
        )
        if m:
            t_start = float(m.group(1))
            t_end = float(m.group(2))
            frames = int(m.group(3))
            bytes_val = int(m.group(4))
            duration = t_end - t_start
            bps = (bytes_val * 8 / duration) if duration > 0 else 0.0

            buckets.append({
                "interval_start": round(t_start, 3),
                "interval_end": round(t_end, 3),
                "frames": frames,
                "bytes": bytes_val,
                "bits_per_second": round(bps, 2),
            })

    return buckets


# ---------------------------------------------------------------------------
# get_expert_info (metadata version — security.py also has one)
# ---------------------------------------------------------------------------

def get_expert_info(file_path: str, min_severity: str = "warn") -> dict:
    """
    Get expert info items from tshark.

    Args:
        file_path: Path to PCAP file.
        min_severity: Minimum severity to include: chat, note, warn, error.

    Returns:
        {items, counts_by_severity, total}
    Each item: {severity, group, protocol, summary, count}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "items": [],
            "counts_by_severity": {"error": 0, "warn": 0, "note": 0, "chat": 0},
            "total": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    stdout = run_tshark_stat(normalized, "expert", timeout=60)

    severity_order = {"chat": 0, "note": 1, "warn": 2, "error": 3}
    min_level = severity_order.get(min_severity.lower(), 1)

    items = _parse_expert_info(stdout)
    filtered = [
        item for item in items
        if severity_order.get(item.get("severity", "").lower(), 0) >= min_level
    ]

    counts: dict[str, int] = {"error": 0, "warn": 0, "note": 0, "chat": 0}
    for item in filtered:
        sev = item.get("severity", "").lower()
        if sev in counts:
            counts[sev] += item.get("count", 1)

    return {
        "file": normalized,
        "items": filtered,
        "counts_by_severity": counts,
        "total": len(filtered),
    }


def _parse_expert_info(output: str) -> list[dict]:
    """Parse tshark expert info output."""
    items = []
    in_section = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if "Expert Information" in stripped:
            in_section = True
            continue

        if not in_section:
            continue

        if stripped.startswith("=") or stripped.startswith("-"):
            continue
        if re.search(r"Severity|Group|Protocol|Summary|Count", stripped, re.IGNORECASE):
            continue

        # Typical line: Error    Malformed    TCP    Malformed packet    1
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) >= 3:
            try:
                items.append({
                    "severity": parts[0].strip(),
                    "group": parts[1].strip() if len(parts) > 1 else "",
                    "protocol": parts[2].strip() if len(parts) > 2 else "",
                    "summary": parts[3].strip() if len(parts) > 3 else "",
                    "count": _safe_int(parts[4]) if len(parts) > 4 else 1,
                })
            except (IndexError, ValueError):
                pass

    return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(s: str) -> int:
    try:
        return int(str(s).replace(",", "").strip())
    except (ValueError, TypeError):
        return 0


def _safe_float(s: str) -> float:
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return 0.0
