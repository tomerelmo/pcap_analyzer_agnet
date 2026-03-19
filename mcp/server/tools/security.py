import logging
import re
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# detect_port_scan
# ---------------------------------------------------------------------------

def detect_port_scan(file_path: str) -> dict:
    """
    Detect port scanning activity via SYN packets to many distinct ports.

    Also detects ICMP echo sweeps.

    Returns:
        {file, port_scans, icmp_sweeps, total_suspicious_sources, risk_level}
    Each port scan: {scanner, target, ports_probed, unique_ports, scan_type}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "port_scans": [],
            "icmp_sweeps": [],
            "total_suspicious_sources": [],
            "risk_level": "low",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # SYN packets (no ACK)
    syn_fields = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.dstport",
    ]
    syn_rows = run_tshark_fields(
        normalized,
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        syn_fields,
        timeout=30,
    )

    # Group by (src, dst) -> set of dest ports
    scan_map: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in syn_rows:
        src = row.get("ip.src", "").strip()
        dst = row.get("ip.dst", "").strip()
        dport = row.get("tcp.dstport", "").strip()
        if src and dst and dport:
            scan_map[(src, dst)].add(dport)

    port_scans = []
    suspicious_sources: set[str] = set()

    for (src, dst), ports in scan_map.items():
        if len(ports) >= 15:
            port_scans.append({
                "scanner": src,
                "target": dst,
                "unique_ports": len(ports),
                "ports_probed": sorted(list(ports))[:100],
                "scan_type": "tcp_syn_scan",
            })
            suspicious_sources.add(src)

    # ICMP sweep detection
    icmp_fields = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "icmp.type",
    ]
    icmp_rows = run_tshark_fields(
        normalized,
        "icmp.type == 8",
        icmp_fields,
        timeout=30,
    )

    icmp_by_src: dict[str, set[str]] = defaultdict(set)
    for row in icmp_rows:
        src = row.get("ip.src", "").strip()
        dst = row.get("ip.dst", "").strip()
        if src and dst:
            icmp_by_src[src].add(dst)

    icmp_sweeps = []
    for src, targets in icmp_by_src.items():
        if len(targets) >= 10:
            icmp_sweeps.append({
                "scanner": src,
                "unique_targets": len(targets),
                "targets_probed": sorted(list(targets))[:50],
                "scan_type": "icmp_sweep",
            })
            suspicious_sources.add(src)

    if not port_scans and not icmp_sweeps:
        risk_level = "low"
    elif len(port_scans) <= 1 and not icmp_sweeps:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "file": normalized,
        "port_scans": sorted(port_scans, key=lambda x: x["unique_ports"], reverse=True),
        "icmp_sweeps": icmp_sweeps,
        "total_suspicious_sources": list(suspicious_sources),
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# detect_beaconing
# ---------------------------------------------------------------------------

def detect_beaconing(file_path: str) -> dict:
    """
    Detect potential C2 beaconing via analysis of connection interval regularity.

    Groups SYN packets by (src, dst, dstport) and checks for low jitter intervals.

    Returns:
        {file, potential_beacons, risk_level}
    Each beacon: {src, dst, port, interval_seconds, jitter, connection_count}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "potential_beacons": [],
            "risk_level": "low",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tcp.dstport",
    ]

    rows = run_tshark_fields(
        normalized,
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        fields,
        timeout=30,
    )

    # Group by (src, dst, dstport) -> list of timestamps
    flow_times: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for row in rows:
        src = row.get("ip.src", "").strip()
        dst = row.get("ip.dst", "").strip()
        dport = row.get("tcp.dstport", "").strip()
        t_str = row.get("frame.time_relative", "").strip()

        if not (src and dst and dport and t_str):
            continue

        try:
            t = float(t_str)
            flow_times[(src, dst, dport)].append(t)
        except ValueError:
            continue

    potential_beacons = []

    for (src, dst, dport), timestamps in flow_times.items():
        if len(timestamps) < 5:
            continue

        timestamps_sorted = sorted(timestamps)
        intervals = [
            timestamps_sorted[i + 1] - timestamps_sorted[i]
            for i in range(len(timestamps_sorted) - 1)
        ]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stdev = variance ** 0.5
        jitter = stdev / mean_interval  # coefficient of variation

        # Low jitter (< 0.2) with > 5 connections = potential beacon
        if jitter < 0.2 and len(timestamps) > 5:
            potential_beacons.append({
                "src": src,
                "dst": dst,
                "port": dport,
                "interval_seconds": round(mean_interval, 3),
                "jitter": round(jitter, 4),
                "connection_count": len(timestamps),
            })

    potential_beacons.sort(key=lambda b: b["jitter"])

    if not potential_beacons:
        risk_level = "low"
    elif len(potential_beacons) <= 2:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "file": normalized,
        "potential_beacons": potential_beacons,
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# find_cleartext_credentials
# ---------------------------------------------------------------------------

def find_cleartext_credentials(file_path: str) -> dict:
    """
    Find protocols that transmit credentials in cleartext.

    Checks: FTP, HTTP Basic Auth, SMTP AUTH.

    Returns:
        {file, findings, count, protocols_affected, risk_level}
    Each finding: {protocol, frame_number, ip_src, ip_dst, credential_type}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "findings": [],
            "count": 0,
            "protocols_affected": [],
            "risk_level": "low",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    findings = []
    protocols_found: set[str] = set()

    # FTP USER command
    ftp_user_rows = run_tshark_fields(
        normalized,
        "ftp.request.command == \"USER\"",
        ["frame.number", "ip.src", "ip.dst", "ftp.request.arg"],
        timeout=30,
    )
    for row in ftp_user_rows:
        findings.append({
            "protocol": "FTP",
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "credential_type": "username",
            "value": row.get("ftp.request.arg", ""),
        })
        protocols_found.add("FTP")

    # FTP PASS command
    ftp_pass_rows = run_tshark_fields(
        normalized,
        "ftp.request.command == \"PASS\"",
        ["frame.number", "ip.src", "ip.dst"],
        timeout=30,
    )
    for row in ftp_pass_rows:
        findings.append({
            "protocol": "FTP",
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "credential_type": "password",
            "value": "[REDACTED]",
        })
        protocols_found.add("FTP")

    # HTTP Basic Authorization header
    http_auth_rows = run_tshark_fields(
        normalized,
        "http.authorization",
        ["frame.number", "ip.src", "ip.dst", "http.authorization"],
        timeout=30,
    )
    for row in http_auth_rows:
        auth_val = row.get("http.authorization", "").strip()
        findings.append({
            "protocol": "HTTP",
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "credential_type": "http_authorization",
            "value": auth_val[:80] if auth_val else "",
        })
        protocols_found.add("HTTP")

    # SMTP AUTH
    smtp_auth_rows = run_tshark_fields(
        normalized,
        "smtp.req.command == \"AUTH\"",
        ["frame.number", "ip.src", "ip.dst", "smtp.req.command"],
        timeout=30,
    )
    for row in smtp_auth_rows:
        findings.append({
            "protocol": "SMTP",
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "credential_type": "smtp_auth",
            "value": "[AUTH command]",
        })
        protocols_found.add("SMTP")

    # POP3 USER/PASS
    pop3_rows = run_tshark_fields(
        normalized,
        "pop.request.command == \"USER\" || pop.request.command == \"PASS\"",
        ["frame.number", "ip.src", "ip.dst", "pop.request.command"],
        timeout=30,
    )
    for row in pop3_rows:
        cmd = row.get("pop.request.command", "").strip()
        findings.append({
            "protocol": "POP3",
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "credential_type": cmd.lower(),
            "value": "[REDACTED]" if cmd.upper() == "PASS" else "",
        })
        protocols_found.add("POP3")

    risk_level = "high" if findings else "low"

    return {
        "file": normalized,
        "findings": findings,
        "count": len(findings),
        "protocols_affected": list(protocols_found),
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# detect_data_exfiltration
# ---------------------------------------------------------------------------

def detect_data_exfiltration(file_path: str) -> dict:
    """
    Detect potential data exfiltration patterns.

    Checks:
    - Large outbound transfers (high byte asymmetry)
    - DNS tunneling indicators
    - Large ICMP payloads

    Returns:
        {file, large_uploads, dns_tunnel_indicators, icmp_tunnel_indicators,
         total_suspicious_flows, risk_level}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "large_uploads": [],
            "dns_tunnel_indicators": [],
            "icmp_tunnel_indicators": [],
            "total_suspicious_flows": 0,
            "risk_level": "low",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Get TCP conversations for asymmetry analysis
    from tools.metadata import get_conversations
    conv_result = get_conversations(normalized, proto="tcp")
    conversations = conv_result.get("conversations", [])

    large_uploads = []
    for conv in conversations:
        bytes_a_to_b = conv.get("bytes_a_to_b", 0)
        bytes_b_to_a = conv.get("bytes_b_to_a", 0)

        # Flag: > 1MB outbound AND ratio > 10:1
        if bytes_a_to_b > 1_000_000 and bytes_b_to_a > 0:
            ratio = bytes_a_to_b / bytes_b_to_a
            if ratio > 10:
                large_uploads.append({
                    "src": conv.get("src", ""),
                    "dst": conv.get("dst", ""),
                    "bytes_outbound": bytes_a_to_b,
                    "bytes_inbound": bytes_b_to_a,
                    "asymmetry_ratio": round(ratio, 2),
                    "duration_seconds": conv.get("duration", 0),
                })

    # DNS tunneling indicators (TXT + long domains)
    dns_fields = [
        "frame.number",
        "ip.src",
        "dns.qry.name",
        "dns.qry.type",
    ]
    dns_rows = run_tshark_fields(
        normalized,
        "dns && dns.flags.response == 0",
        dns_fields,
        timeout=30,
    )

    dns_tunnel_indicators = []
    txt_by_src: dict[str, int] = defaultdict(int)
    long_domain_by_src: dict[str, int] = defaultdict(int)

    for row in dns_rows:
        qtype = row.get("dns.qry.type", "").strip()
        qname = row.get("dns.qry.name", "").strip()
        src = row.get("ip.src", "").strip()

        if qtype == "16":  # TXT
            txt_by_src[src] += 1
        if qname and len(qname) > 50:
            long_domain_by_src[src] += 1

    for src, count in txt_by_src.items():
        if count > 10:
            dns_tunnel_indicators.append({
                "ip_src": src,
                "indicator": "high_txt_query_volume",
                "count": count,
            })

    for src, count in long_domain_by_src.items():
        if count > 5:
            dns_tunnel_indicators.append({
                "ip_src": src,
                "indicator": "long_domain_names",
                "count": count,
            })

    # ICMP tunnel detection — large ICMP payloads
    icmp_fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "frame.len",
        "icmp.type",
    ]
    icmp_rows = run_tshark_fields(
        normalized,
        "icmp",
        icmp_fields,
        timeout=30,
    )

    icmp_tunnel_indicators = []
    icmp_large_by_flow: dict[tuple[str, str], list[int]] = defaultdict(list)

    for row in icmp_rows:
        icmp_type = row.get("icmp.type", "").strip()
        if icmp_type not in ("0", "8"):
            continue
        src = row.get("ip.src", "").strip()
        dst = row.get("ip.dst", "").strip()
        try:
            frame_len = int(row.get("frame.len", "0").strip())
        except (ValueError, TypeError):
            frame_len = 0

        # ICMP header is ~28 bytes; payload > 100 bytes is unusual
        if frame_len > 128:
            icmp_large_by_flow[(src, dst)].append(frame_len)

    for (src, dst), sizes in icmp_large_by_flow.items():
        if len(sizes) > 3:
            icmp_tunnel_indicators.append({
                "ip_src": src,
                "ip_dst": dst,
                "packet_count": len(sizes),
                "avg_frame_len": round(sum(sizes) / len(sizes), 1),
                "indicator": "large_icmp_payload",
            })

    total_suspicious = len(large_uploads) + len(dns_tunnel_indicators) + len(icmp_tunnel_indicators)

    if total_suspicious == 0:
        risk_level = "low"
    elif total_suspicious <= 3:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "file": normalized,
        "large_uploads": large_uploads,
        "dns_tunnel_indicators": dns_tunnel_indicators,
        "icmp_tunnel_indicators": icmp_tunnel_indicators,
        "total_suspicious_flows": total_suspicious,
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# get_expert_info
# ---------------------------------------------------------------------------

def get_expert_info(file_path: str, min_severity: str = "warn") -> dict:
    """
    Get expert info items from tshark, grouped by severity and protocol.

    Args:
        file_path: Path to PCAP file.
        min_severity: Minimum severity level: chat, note, warn, error.

    Returns:
        {file, items, by_severity, by_protocol, error_count, warn_count,
         note_count, top_issues}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "items": [],
            "by_severity": {},
            "by_protocol": {},
            "error_count": 0,
            "warn_count": 0,
            "note_count": 0,
            "top_issues": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    stdout = run_tshark_stat(normalized, "expert", timeout=60)

    severity_order = {"chat": 0, "note": 1, "warn": 2, "error": 3}
    min_level = severity_order.get(min_severity.lower(), 1)

    all_items = _parse_expert_output(stdout)

    filtered = [
        item for item in all_items
        if severity_order.get(item.get("severity", "").lower(), 0) >= min_level
    ]

    by_severity: dict[str, list] = defaultdict(list)
    by_protocol: dict[str, list] = defaultdict(list)
    error_count = 0
    warn_count = 0
    note_count = 0

    for item in filtered:
        sev = item.get("severity", "unknown").lower()
        proto = item.get("protocol", "unknown")
        by_severity[sev].append(item)
        by_protocol[proto].append(item)

        if sev == "error":
            error_count += item.get("count", 1)
        elif sev == "warn":
            warn_count += item.get("count", 1)
        elif sev == "note":
            note_count += item.get("count", 1)

    # Top issues by count
    top_issues = sorted(filtered, key=lambda i: i.get("count", 1), reverse=True)[:10]

    return {
        "file": normalized,
        "items": filtered,
        "by_severity": {k: v for k, v in by_severity.items()},
        "by_protocol": {k: v for k, v in by_protocol.items()},
        "error_count": error_count,
        "warn_count": warn_count,
        "note_count": note_count,
        "top_issues": top_issues,
    }


def _parse_expert_output(output: str) -> list[dict]:
    """Parse tshark -z expert output into structured items."""
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

        # Skip header row
        if re.match(r"Severity\s+Group\s+Protocol", stripped, re.IGNORECASE):
            continue

        # Multi-space separated columns
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) >= 3:
            try:
                count_str = parts[-1].strip() if len(parts) > 4 else "1"
                count = int(count_str) if count_str.isdigit() else 1

                items.append({
                    "severity": parts[0].strip(),
                    "group": parts[1].strip() if len(parts) > 1 else "",
                    "protocol": parts[2].strip() if len(parts) > 2 else "",
                    "summary": parts[3].strip() if len(parts) > 3 else "",
                    "count": count,
                })
            except (IndexError, ValueError):
                pass

    return items
