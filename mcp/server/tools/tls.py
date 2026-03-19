import logging
from collections import defaultdict
from tools.files import validate_pcap_path
from tools.helpers import run_tshark_fields, get_max_results

logger = logging.getLogger(__name__)

# TLS alert code to name mapping
TLS_ALERT_NAMES = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "21": "decryption_failed",
    "22": "record_overflow",
    "40": "handshake_failure",
    "42": "bad_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "49": "access_denied",
    "50": "decode_error",
    "51": "decrypt_error",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "90": "user_canceled",
    "100": "no_renegotiation",
    "110": "unsupported_extension",
    "120": "certificate_unobtainable",
}

# TLS version code to human label
TLS_VERSION_NAMES = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
}

WEAK_TLS_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}

# TLS handshake type codes
HANDSHAKE_TYPES = {
    "1": "ClientHello",
    "2": "ServerHello",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
}


# ---------------------------------------------------------------------------
# tls_handshake_summary
# ---------------------------------------------------------------------------

def tls_handshake_summary(file_path: str) -> dict:
    """
    Summarize TLS handshake data from a capture file.

    Returns:
        {file, handshakes, total_tls_streams, by_version, weak_version_count,
         cipher_suites, sni_list}
    Each handshake: {stream, ip_src, ip_dst, handshake_type, version, cipher_suite, sni}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "handshakes": [],
            "total_tls_streams": 0,
            "by_version": {},
            "weak_version_count": 0,
            "cipher_suites": [],
            "sni_list": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "tls.handshake.type",
        "tls.record.version",
        "tls.handshake.version",
        "tls.handshake.ciphersuites",
        "tls.handshake.extensions_server_name",
    ]

    rows = run_tshark_fields(
        normalized,
        "tls.handshake",
        fields,
        timeout=30,
    )

    handshakes = []
    streams_seen: set[str] = set()
    by_version: dict[str, int] = defaultdict(int)
    cipher_suites_seen: set[str] = set()
    sni_seen: set[str] = set()

    for row in rows:
        stream = row.get("tcp.stream", "")
        if stream:
            streams_seen.add(stream)

        raw_version = (
            row.get("tls.handshake.version", "")
            or row.get("tls.record.version", "")
        ).strip()
        version_label = TLS_VERSION_NAMES.get(raw_version, raw_version or "unknown")

        if version_label:
            by_version[version_label] += 1

        cipher = row.get("tls.handshake.ciphersuites", "").strip()
        if cipher:
            cipher_suites_seen.add(cipher)

        sni = row.get("tls.handshake.extensions_server_name", "").strip()
        if sni:
            sni_seen.add(sni)

        hs_type_code = row.get("tls.handshake.type", "").strip()
        hs_type_name = HANDSHAKE_TYPES.get(hs_type_code, f"type_{hs_type_code}")

        handshakes.append({
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "tcp_stream": stream,
            "handshake_type": hs_type_name,
            "version": version_label,
            "cipher_suite": cipher,
            "sni": sni,
        })

    weak_version_count = sum(
        count for version, count in by_version.items()
        if version in WEAK_TLS_VERSIONS
    )

    return {
        "file": normalized,
        "handshakes": handshakes,
        "total_tls_streams": len(streams_seen),
        "by_version": dict(by_version),
        "weak_version_count": weak_version_count,
        "cipher_suites": list(cipher_suites_seen),
        "sni_list": list(sni_seen),
    }


# ---------------------------------------------------------------------------
# tls_alerts
# ---------------------------------------------------------------------------

def tls_alerts(file_path: str) -> dict:
    """
    Extract TLS alert messages from a capture file.

    Returns:
        {file, alerts, count, by_alert_type, fatal_count, warning_count}
    Each alert: {frame_number, time_relative, ip_src, ip_dst, alert_level, alert_message}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "alerts": [],
            "count": 0,
            "by_alert_type": {},
            "fatal_count": 0,
            "warning_count": 0,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "tls.alert.level",
        "tls.alert.message",
    ]

    rows = run_tshark_fields(
        normalized,
        "tls.alert.message",
        fields,
        timeout=30,
    )

    alerts = []
    by_alert_type: dict[str, int] = defaultdict(int)
    fatal_count = 0
    warning_count = 0

    for row in rows:
        alert_code = row.get("tls.alert.message", "").strip()
        alert_name = TLS_ALERT_NAMES.get(alert_code, alert_code or "unknown")

        level_code = row.get("tls.alert.level", "").strip()
        # Level 1 = warning, 2 = fatal
        if level_code == "2":
            level_name = "fatal"
            fatal_count += 1
        elif level_code == "1":
            level_name = "warning"
            warning_count += 1
        else:
            level_name = level_code or "unknown"

        by_alert_type[alert_name] += 1

        alerts.append({
            "frame_number": row.get("frame.number", ""),
            "time_relative": row.get("frame.time_relative", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "alert_level": level_name,
            "alert_message": alert_name,
        })

    return {
        "file": normalized,
        "alerts": alerts,
        "count": len(alerts),
        "by_alert_type": dict(by_alert_type),
        "fatal_count": fatal_count,
        "warning_count": warning_count,
    }


# ---------------------------------------------------------------------------
# tls_certificate_info
# ---------------------------------------------------------------------------

def tls_certificate_info(file_path: str) -> dict:
    """
    Extract TLS certificate information from a capture file.

    Returns:
        {file, certificates, expired_count, warnings}
    Each certificate: {ip_src, ip_dst, sni, not_before, not_after}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "certificates": [],
            "expired_count": 0,
            "warnings": [],
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tls.handshake.extensions_server_name",
        "tls.x509af.validity.not_before",
        "tls.x509af.validity.not_after",
    ]

    # Filter to Certificate handshake messages (type 11)
    rows = run_tshark_fields(
        normalized,
        "tls.handshake.type == 11",
        fields,
        timeout=30,
    )

    certificates = []
    expired_count = 0
    warnings = []

    for row in rows:
        not_before = row.get("tls.x509af.validity.not_before", "").strip()
        not_after = row.get("tls.x509af.validity.not_after", "").strip()
        sni = row.get("tls.handshake.extensions_server_name", "").strip()

        cert = {
            "frame_number": row.get("frame.number", ""),
            "ip_src": row.get("ip.src", ""),
            "ip_dst": row.get("ip.dst", ""),
            "sni": sni,
            "not_before": not_before,
            "not_after": not_after,
        }
        certificates.append(cert)

        # Flag if we can detect expiry (string contains year info)
        if not_after:
            # Check for obviously old expiry dates containing years < 2020
            import re
            year_match = re.search(r"\b(19\d{2}|200\d|201\d)\b", not_after)
            if year_match:
                expired_count += 1
                warnings.append(
                    f"Potentially expired certificate detected (not_after: {not_after}) "
                    f"from {cert['ip_src']} to {cert['ip_dst']}"
                )

    # Deduplicate warnings
    seen_warnings: set[str] = set()
    unique_warnings = []
    for w in warnings:
        if w not in seen_warnings:
            seen_warnings.add(w)
            unique_warnings.append(w)

    return {
        "file": normalized,
        "certificates": certificates,
        "expired_count": expired_count,
        "warnings": unique_warnings,
    }
