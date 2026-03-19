import logging
import re
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)

# DHCP message type codes
DHCP_MSG_TYPES = {
    "1": "DISCOVER",
    "2": "OFFER",
    "3": "REQUEST",
    "4": "DECLINE",
    "5": "ACK",
    "6": "NAK",
    "7": "RELEASE",
    "8": "INFORM",
}

# ICMP type codes
ICMP_TYPES = {
    "0": "echo_reply",
    "3": "dest_unreachable",
    "4": "source_quench",
    "5": "redirect",
    "8": "echo_request",
    "9": "router_advertisement",
    "10": "router_solicitation",
    "11": "time_exceeded",
    "12": "parameter_problem",
    "13": "timestamp",
    "14": "timestamp_reply",
    "30": "traceroute",
}


# ---------------------------------------------------------------------------
# dhcp_summary
# ---------------------------------------------------------------------------

def dhcp_summary(file_path: str) -> dict:
    """
    Summarize DHCP traffic from a capture file.

    Detects rogue DHCP servers (multiple OFFER sources).

    Returns:
        {file, total_dhcp_packets, by_message_type, dhcp_servers, clients,
         rogue_server_warning, warnings}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_dhcp_packets": 0,
            "by_message_type": {},
            "dhcp_servers": [],
            "clients": [],
            "rogue_server_warning": False,
            "warnings": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "dhcp.type",
        "dhcp.hw.mac_addr",
        "dhcp.option.dhcp_server_id",
        "dhcp.your_ip_addr",
        "dhcp.option.host_name",
    ]

    rows = run_tshark_fields(
        normalized,
        "dhcp or bootp",
        fields,
        timeout=30,
    )

    by_message_type: dict[str, int] = defaultdict(int)
    dhcp_servers: set[str] = set()
    clients: dict[str, dict] = {}
    offer_sources: set[str] = set()

    for row in rows:
        msg_type_code = row.get("dhcp.type", "").strip()
        msg_type_name = DHCP_MSG_TYPES.get(msg_type_code, msg_type_code or "unknown")
        by_message_type[msg_type_name] += 1

        server_id = row.get("dhcp.option.dhcp_server_id", "").strip()
        if server_id:
            dhcp_servers.add(server_id)

        # Track OFFER sources for rogue detection
        if msg_type_code == "2":
            ip_src = row.get("ip.src", "").strip()
            if ip_src:
                offer_sources.add(ip_src)

        # Track clients by MAC address
        mac = row.get("dhcp.hw.mac_addr", "").strip()
        if mac:
            assigned_ip = row.get("dhcp.your_ip_addr", "").strip()
            hostname = row.get("dhcp.option.host_name", "").strip()
            if mac not in clients:
                clients[mac] = {"mac": mac, "assigned_ips": [], "hostnames": []}
            if assigned_ip and assigned_ip not in clients[mac]["assigned_ips"]:
                clients[mac]["assigned_ips"].append(assigned_ip)
            if hostname and hostname not in clients[mac]["hostnames"]:
                clients[mac]["hostnames"].append(hostname)

    warnings = []
    rogue_server_warning = False

    if len(offer_sources) > 1:
        rogue_server_warning = True
        warnings.append(
            f"Multiple DHCP OFFER sources detected: {', '.join(sorted(offer_sources))} "
            "— possible rogue DHCP server"
        )

    return {
        "file": normalized,
        "total_dhcp_packets": len(rows),
        "by_message_type": dict(by_message_type),
        "dhcp_servers": list(dhcp_servers),
        "clients": list(clients.values()),
        "rogue_server_warning": rogue_server_warning,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# arp_analysis
# ---------------------------------------------------------------------------

def arp_analysis(file_path: str) -> dict:
    """
    Analyze ARP traffic for anomalies: gratuitous ARP, IP conflicts, flooding.

    Returns:
        {file, total_arp, gratuitous_arp, ip_mac_conflicts, arp_flood_detected,
         ip_to_mac_table, warnings}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_arp": 0,
            "gratuitous_arp": [],
            "ip_mac_conflicts": [],
            "arp_flood_detected": False,
            "ip_to_mac_table": {},
            "warnings": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "arp.opcode",
        "arp.src.proto_ipv4",
        "arp.src.hw_mac",
        "arp.dst.proto_ipv4",
        "arp.dst.hw_mac",
    ]

    rows = run_tshark_fields(
        normalized,
        "arp",
        fields,
        timeout=30,
    )

    total_arp = len(rows)
    gratuitous_arp = []
    ip_to_mac: dict[str, set[str]] = defaultdict(set)
    arp_request_times: list[float] = []
    warnings = []

    for row in rows:
        opcode = row.get("arp.opcode", "").strip()
        src_ip = row.get("arp.src.proto_ipv4", "").strip()
        src_mac = row.get("arp.src.hw_mac", "").strip()
        dst_ip = row.get("arp.dst.proto_ipv4", "").strip()
        t_str = row.get("frame.time_relative", "").strip()

        # Track IP-to-MAC mappings
        if src_ip and src_mac:
            ip_to_mac[src_ip].add(src_mac)

        # Gratuitous ARP: reply where src IP == dst IP
        if opcode == "2" and src_ip and src_ip == dst_ip:
            gratuitous_arp.append({
                "frame_number": row.get("frame.number", ""),
                "time_relative": t_str,
                "ip": src_ip,
                "mac": src_mac,
            })

        # Track request times for flood detection
        if opcode == "1":
            try:
                arp_request_times.append(float(t_str))
            except (ValueError, TypeError):
                pass

    # ARP spoofing detection: same IP mapped to multiple MACs
    ip_mac_conflicts = []
    for ip, macs in ip_to_mac.items():
        if len(macs) > 1:
            ip_mac_conflicts.append({
                "ip": ip,
                "mac_addresses": list(macs),
            })
            warnings.append(
                f"ARP spoofing indicator: IP {ip} seen with MACs {', '.join(sorted(macs))}"
            )

    # ARP flood detection: > 50 requests per second
    arp_flood_detected = False
    if len(arp_request_times) > 50:
        arp_request_times_sorted = sorted(arp_request_times)
        # Check any 1-second window
        for i, t in enumerate(arp_request_times_sorted):
            window_end = t + 1.0
            count_in_window = sum(
                1 for t2 in arp_request_times_sorted[i:]
                if t2 <= window_end
            )
            if count_in_window > 50:
                arp_flood_detected = True
                warnings.append(
                    f"ARP flood detected: {count_in_window} ARP requests in 1 second"
                )
                break

    # Convert sets to lists for JSON serialization
    ip_to_mac_serializable = {ip: list(macs) for ip, macs in ip_to_mac.items()}

    return {
        "file": normalized,
        "total_arp": total_arp,
        "gratuitous_arp": gratuitous_arp,
        "ip_mac_conflicts": ip_mac_conflicts,
        "arp_flood_detected": arp_flood_detected,
        "ip_to_mac_table": ip_to_mac_serializable,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# icmp_analysis
# ---------------------------------------------------------------------------

def icmp_analysis(file_path: str) -> dict:
    """
    Analyze ICMP traffic: types, unreachables, large payloads, tunneling indicators.

    Returns:
        {file, total_icmp, by_type, echo_pairs, unreachable_destinations,
         large_payload_count, potential_tunnel_flows}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_icmp": 0,
            "by_type": {},
            "echo_pairs": 0,
            "unreachable_destinations": [],
            "large_payload_count": 0,
            "potential_tunnel_flows": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.code",
        "frame.len",
    ]

    rows = run_tshark_fields(
        normalized,
        "icmp",
        fields,
        timeout=30,
    )

    total_icmp = len(rows)
    by_type: dict[str, int] = defaultdict(int)
    echo_requests = 0
    echo_replies = 0
    unreachable_dsts: set[str] = set()
    large_payload_count = 0
    tunnel_flows: dict[tuple[str, str], list[int]] = defaultdict(list)

    for row in rows:
        icmp_type = row.get("icmp.type", "").strip()
        type_name = ICMP_TYPES.get(icmp_type, f"type_{icmp_type}")
        by_type[type_name] += 1

        ip_src = row.get("ip.src", "").strip()
        ip_dst = row.get("ip.dst", "").strip()

        if icmp_type == "8":
            echo_requests += 1
        elif icmp_type == "0":
            echo_replies += 1
        elif icmp_type == "3":
            # Destination unreachable
            if ip_dst:
                unreachable_dsts.add(ip_dst)

        try:
            frame_len = int(row.get("frame.len", "0").strip())
        except (ValueError, TypeError):
            frame_len = 0

        # Large payload: frame > 128 bytes (ICMP header ~28 bytes, so data > 100 bytes)
        if frame_len > 128:
            large_payload_count += 1
            if icmp_type in ("0", "8") and ip_src and ip_dst:
                tunnel_flows[(ip_src, ip_dst)].append(frame_len)

    # Identify potential tunnel flows (consistent large payloads)
    potential_tunnel_flows = []
    for (src, dst), sizes in tunnel_flows.items():
        if len(sizes) > 3:
            potential_tunnel_flows.append({
                "ip_src": src,
                "ip_dst": dst,
                "packet_count": len(sizes),
                "avg_frame_len": round(sum(sizes) / len(sizes), 1),
                "max_frame_len": max(sizes),
            })

    echo_pairs = min(echo_requests, echo_replies)

    return {
        "file": normalized,
        "total_icmp": total_icmp,
        "by_type": dict(by_type),
        "echo_pairs": echo_pairs,
        "unreachable_destinations": list(unreachable_dsts),
        "large_payload_count": large_payload_count,
        "potential_tunnel_flows": potential_tunnel_flows,
    }


# ---------------------------------------------------------------------------
# smb_summary
# ---------------------------------------------------------------------------

def smb_summary(file_path: str) -> dict:
    """
    Summarize SMB/SMB2 traffic from a capture file.

    Returns:
        {file, total_smb_packets, smb_version, operations, auth_failures,
         unique_shares, file_operations}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_smb_packets": 0,
            "smb_version": [],
            "operations": {},
            "auth_failures": [],
            "unique_shares": [],
            "file_operations": {},
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # SMB1 fields
    smb1_fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "smb.cmd",
        "smb.nt_status",
        "smb.file",
    ]
    smb1_rows = run_tshark_fields(
        normalized,
        "smb",
        smb1_fields,
        timeout=30,
    )

    # SMB2 fields
    smb2_fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "smb2.cmd",
        "smb2.nt_status",
        "smb2.filename",
        "smb2.tree",
    ]
    smb2_rows = run_tshark_fields(
        normalized,
        "smb2",
        smb2_fields,
        timeout=30,
    )

    total_smb_packets = len(smb1_rows) + len(smb2_rows)
    smb_versions = []
    if smb1_rows:
        smb_versions.append("SMB1")
    if smb2_rows:
        smb_versions.append("SMB2")

    operations: dict[str, int] = defaultdict(int)
    auth_failures = []
    shares: set[str] = set()
    file_operations: dict[str, int] = defaultdict(int)

    # SMB1 NT status codes indicating auth failure
    AUTH_FAIL_CODES = {
        "0xc000006d",  # STATUS_LOGON_FAILURE
        "0xc000006e",  # STATUS_ACCOUNT_RESTRICTION
        "0xc0000064",  # STATUS_NO_SUCH_USER
        "0xc000006a",  # STATUS_WRONG_PASSWORD
        "0xc0000234",  # STATUS_ACCOUNT_LOCKED_OUT
    }

    # Known SMB2 command names
    SMB2_CMDS = {
        "0": "NEGOTIATE", "1": "SESSION_SETUP", "2": "LOGOFF",
        "3": "TREE_CONNECT", "4": "TREE_DISCONNECT", "5": "CREATE",
        "6": "CLOSE", "7": "FLUSH", "8": "READ", "9": "WRITE",
        "10": "IOCTL", "11": "CANCEL", "12": "ECHO", "13": "QUERY_DIRECTORY",
        "14": "CHANGE_NOTIFY", "15": "QUERY_INFO", "16": "SET_INFO",
        "17": "OPLOCK_BREAK",
    }

    for row in smb2_rows:
        cmd_code = row.get("smb2.cmd", "").strip()
        cmd_name = SMB2_CMDS.get(cmd_code, f"cmd_{cmd_code}")
        operations[cmd_name] += 1

        nt_status = row.get("smb2.nt_status", "").strip().lower()
        if nt_status in AUTH_FAIL_CODES:
            auth_failures.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": row.get("ip.src", ""),
                "ip_dst": row.get("ip.dst", ""),
                "nt_status": nt_status,
                "version": "SMB2",
            })

        tree = row.get("smb2.tree", "").strip()
        if tree:
            shares.add(tree)

        filename = row.get("smb2.filename", "").strip()
        if filename and cmd_code in ("5", "6", "8", "9"):
            op_name = SMB2_CMDS.get(cmd_code, cmd_code)
            file_operations[op_name] += 1

    for row in smb1_rows:
        cmd = row.get("smb.cmd", "").strip()
        operations[f"smb1_{cmd}"] += 1

        nt_status = row.get("smb.nt_status", "").strip().lower()
        if nt_status in AUTH_FAIL_CODES:
            auth_failures.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": row.get("ip.src", ""),
                "ip_dst": row.get("ip.dst", ""),
                "nt_status": nt_status,
                "version": "SMB1",
            })

    return {
        "file": normalized,
        "total_smb_packets": total_smb_packets,
        "smb_version": smb_versions,
        "operations": dict(operations),
        "auth_failures": auth_failures[:50],
        "unique_shares": list(shares),
        "file_operations": dict(file_operations),
    }
