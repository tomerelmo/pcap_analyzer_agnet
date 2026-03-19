import logging
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, run_tshark_stat, get_max_results

logger = logging.getLogger(__name__)

# DNS response code mapping
DNS_RCODES = {
    "1": "FORMERR",
    "2": "SERVFAIL",
    "3": "NXDOMAIN",
    "4": "NOTIMP",
    "5": "REFUSED",
    "6": "YXDOMAIN",
    "7": "YXRRSET",
    "8": "NXRRSET",
    "9": "NOTAUTH",
    "10": "NOTZONE",
}

# DNS query type mapping (common types)
DNS_QTYPES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "255": "ANY",
    "252": "AXFR",
    "251": "IXFR",
}


# ---------------------------------------------------------------------------
# dns_summary
# ---------------------------------------------------------------------------

def dns_summary(file_path: str) -> dict:
    """
    Summarize DNS traffic in a capture file.

    Returns:
        {file, total_queries, total_responses, by_query_type, top_queried_domains,
         nxdomain_count, unique_dns_servers, resolver_ips}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "total_queries": 0,
            "total_responses": 0,
            "by_query_type": {},
            "top_queried_domains": [],
            "nxdomain_count": 0,
            "unique_dns_servers": [],
            "resolver_ips": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # Extract all DNS packets
    fields = [
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "dns.flags.response",
        "dns.qry.name",
        "dns.qry.type",
        "dns.resp.type",
        "dns.flags.rcode",
    ]

    rows = run_tshark_fields(
        normalized,
        "dns",
        fields,
        timeout=30,
    )

    total_queries = 0
    total_responses = 0
    by_query_type: dict[str, int] = defaultdict(int)
    domain_counts: dict[str, int] = defaultdict(int)
    nxdomain_count = 0
    dns_servers: set[str] = set()
    resolver_ips: set[str] = set()

    for row in rows:
        is_response = row.get("dns.flags.response", "").strip() == "1"
        qname = row.get("dns.qry.name", "").strip()
        qtype_code = row.get("dns.qry.type", "").strip()
        rcode = row.get("dns.flags.rcode", "").strip()
        ip_src = row.get("ip.src", "").strip()
        ip_dst = row.get("ip.dst", "").strip()

        if is_response:
            total_responses += 1
            # Response comes from dns server (ip.src) to resolver (ip.dst)
            if ip_src:
                dns_servers.add(ip_src)
            if ip_dst:
                resolver_ips.add(ip_dst)
            if rcode == "3":
                nxdomain_count += 1
        else:
            total_queries += 1
            if qname:
                domain_counts[qname] += 1
            qtype_name = DNS_QTYPES.get(qtype_code, qtype_code or "unknown")
            if qtype_name:
                by_query_type[qtype_name] += 1

    top_domains = sorted(
        [{"domain": d, "count": c} for d, c in domain_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:20]

    return {
        "file": normalized,
        "total_queries": total_queries,
        "total_responses": total_responses,
        "by_query_type": dict(by_query_type),
        "top_queried_domains": top_domains,
        "nxdomain_count": nxdomain_count,
        "unique_dns_servers": list(dns_servers),
        "resolver_ips": list(resolver_ips),
    }


# ---------------------------------------------------------------------------
# dns_failed_queries
# ---------------------------------------------------------------------------

def dns_failed_queries(file_path: str) -> dict:
    """
    Find DNS queries that received error responses.

    Returns:
        {file, failed_queries, count, by_response_code, nxdomain_domains}
    Each query: {frame_number, time_relative, ip_src, ip_dst, query_name, response_code}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "failed_queries": [],
            "count": 0,
            "by_response_code": {},
            "nxdomain_domains": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.flags.rcode",
    ]

    # dns.flags.response==1 and non-zero rcode
    rows = run_tshark_fields(
        normalized,
        "dns.flags.response == 1 && dns.flags.rcode > 0",
        fields,
        timeout=30,
    )

    failed_queries = []
    by_response_code: dict[str, int] = defaultdict(int)
    nxdomain_domains: list[str] = []

    for row in rows:
        rcode = row.get("dns.flags.rcode", "").strip()
        rcode_name = DNS_RCODES.get(rcode, rcode or "unknown")
        by_response_code[rcode_name] += 1

        qname = row.get("dns.qry.name", "").strip()
        if rcode == "3" and qname:
            nxdomain_domains.append(qname)

        failed_queries.append({
            "frame_number": row.get("frame.number", ""),
            "time_relative": row.get("frame.time_relative", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "query_name": qname,
            "response_code": rcode_name,
        })

    # Deduplicate nxdomain domains
    unique_nxdomains = list(dict.fromkeys(nxdomain_domains))

    return {
        "file": normalized,
        "failed_queries": failed_queries,
        "count": len(failed_queries),
        "by_response_code": dict(by_response_code),
        "nxdomain_domains": unique_nxdomains,
    }


# ---------------------------------------------------------------------------
# dns_suspicious_patterns
# ---------------------------------------------------------------------------

def dns_suspicious_patterns(file_path: str) -> dict:
    """
    Detect suspicious DNS patterns: high volume, long domains, DGA, tunneling indicators.

    Returns:
        {file, high_volume_sources, long_domains, nxdomain_rate_pct, txt_queries,
         zone_transfer_attempts, suspicious_indicators, risk_level}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "high_volume_sources": [],
            "long_domains": [],
            "nxdomain_rate_pct": 0.0,
            "txt_queries": [],
            "zone_transfer_attempts": [],
            "suspicious_indicators": [],
            "risk_level": "low",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "ip.src",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.rcode",
        "dns.flags.response",
    ]

    rows = run_tshark_fields(
        normalized,
        "dns",
        fields,
        timeout=30,
    )

    query_count_by_src: dict[str, int] = defaultdict(int)
    long_domains: list[dict] = []
    txt_queries: list[dict] = []
    zone_transfer_attempts: list[dict] = []
    total_queries = 0
    nxdomain_count = 0

    for row in rows:
        is_response = row.get("dns.flags.response", "").strip() == "1"
        qname = row.get("dns.qry.name", "").strip()
        qtype = row.get("dns.qry.type", "").strip()
        ip_src = row.get("ip.src", "").strip()
        rcode = row.get("dns.flags.rcode", "").strip()

        if is_response:
            if rcode == "3":
                nxdomain_count += 1
            continue

        total_queries += 1
        query_count_by_src[ip_src] += 1

        # Long domain detection (>50 chars) — DGA / tunneling indicator
        if qname and len(qname) > 50:
            long_domains.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": ip_src,
                "domain": qname,
                "length": len(qname),
            })

        # TXT record queries — possible DNS tunneling
        if qtype in ("16", "TXT"):
            txt_queries.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": ip_src,
                "domain": qname,
            })

        # Zone transfer attempts
        if qtype in ("252", "AXFR", "251", "IXFR"):
            qtype_name = DNS_QTYPES.get(qtype, qtype)
            zone_transfer_attempts.append({
                "frame_number": row.get("frame.number", ""),
                "ip_src": ip_src,
                "domain": qname,
                "query_type": qtype_name,
            })

    # High volume sources (>100 queries from single source)
    high_volume_sources = [
        {"ip_src": ip, "query_count": count}
        for ip, count in sorted(query_count_by_src.items(), key=lambda x: x[1], reverse=True)
        if count > 100
    ]

    nxdomain_rate_pct = round(
        nxdomain_count / total_queries * 100, 2
    ) if total_queries > 0 else 0.0

    suspicious_indicators = []
    risk_score = 0

    if high_volume_sources:
        suspicious_indicators.append(
            f"High DNS query volume from {len(high_volume_sources)} source(s)"
        )
        risk_score += 2

    if len(long_domains) > 5:
        suspicious_indicators.append(
            f"{len(long_domains)} long domain names detected (possible DGA or DNS tunneling)"
        )
        risk_score += 2

    if nxdomain_rate_pct > 30:
        suspicious_indicators.append(
            f"High NXDOMAIN rate: {nxdomain_rate_pct:.1f}% (possible DGA activity)"
        )
        risk_score += 2

    if txt_queries:
        suspicious_indicators.append(
            f"{len(txt_queries)} TXT record queries detected (possible DNS tunneling)"
        )
        risk_score += 1

    if zone_transfer_attempts:
        suspicious_indicators.append(
            f"{len(zone_transfer_attempts)} zone transfer attempt(s) detected"
        )
        risk_score += 3

    if risk_score == 0:
        risk_level = "low"
    elif risk_score <= 3:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "file": normalized,
        "high_volume_sources": high_volume_sources,
        "long_domains": long_domains[:50],
        "nxdomain_rate_pct": nxdomain_rate_pct,
        "txt_queries": txt_queries[:50],
        "zone_transfer_attempts": zone_transfer_attempts,
        "suspicious_indicators": suspicious_indicators,
        "risk_level": risk_level,
    }


# ---------------------------------------------------------------------------
# dns_response_times
# ---------------------------------------------------------------------------

def dns_response_times(file_path: str) -> dict:
    """
    Analyze DNS response times using tshark SRT statistics.

    Returns:
        {file, avg_ms, max_ms, min_ms, total_measured}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "avg_ms": 0,
            "max_ms": 0,
            "min_ms": 0,
            "total_measured": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    stdout = run_tshark_stat(normalized, "srt,dns", timeout=60)

    avg_ms, max_ms, min_ms, total = _parse_srt_dns(stdout)

    return {
        "file": normalized,
        "avg_ms": avg_ms,
        "max_ms": max_ms,
        "min_ms": min_ms,
        "total_measured": total,
        "raw_stats": stdout.strip(),
    }


def _parse_srt_dns(output: str) -> tuple[float, float, float, int]:
    """Parse DNS SRT output and return (avg_ms, max_ms, min_ms, total)."""
    import re

    avg_ms = 0.0
    max_ms = 0.0
    min_ms = 0.0
    total = 0

    for line in output.splitlines():
        # Look for lines with timing data
        # Typical: DNS SRT Statistics: ... Calls: N  Min: X.Xs  Max: X.Xs  Avg: X.Xs
        m = re.search(
            r"(?:Calls|Total):\s*(\d+).*?Min:\s*([\d.]+)s.*?Max:\s*([\d.]+)s.*?Avg:\s*([\d.]+)s",
            line,
            re.IGNORECASE,
        )
        if m:
            total = int(m.group(1))
            min_ms = round(float(m.group(2)) * 1000, 2)
            max_ms = round(float(m.group(3)) * 1000, 2)
            avg_ms = round(float(m.group(4)) * 1000, 2)
            break

        # Alternative format: tabular
        m2 = re.search(
            r"(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
            line,
        )
        if m2 and total == 0:
            try:
                total = int(m2.group(1))
                min_ms = round(float(m2.group(2)) * 1000, 2)
                max_ms = round(float(m2.group(3)) * 1000, 2)
                avg_ms = round(float(m2.group(4)) * 1000, 2)
            except (ValueError, IndexError):
                pass

    return avg_ms, max_ms, min_ms, total
