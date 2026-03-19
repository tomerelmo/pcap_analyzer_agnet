import os
import subprocess
import logging

logger = logging.getLogger(__name__)


def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """
    Run a subprocess command safely.

    Args:
        cmd: Command as a list of strings (never shell=True).
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, stderr, returncode).
    """
    logger.debug("Running command: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # Never use shell=True
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, " ".join(cmd))
        return "", f"Command timed out after {timeout} seconds", -1
    except FileNotFoundError as e:
        logger.error("Command not found: %s — %s", cmd[0], e)
        return "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        logger.exception("Unexpected error running command: %s", " ".join(cmd))
        return "", f"Unexpected error: {e}", -3


def get_max_results() -> int:
    """Read MAX_PACKET_SLICE_RESULTS from environment, default 200."""
    try:
        return int(os.environ.get("MAX_PACKET_SLICE_RESULTS", "200"))
    except (ValueError, TypeError):
        return 200


def get_max_stream_chars() -> int:
    """Read MAX_STREAM_EXTRACT_CHARS from environment, default 20000."""
    try:
        return int(os.environ.get("MAX_STREAM_EXTRACT_CHARS", "20000"))
    except (ValueError, TypeError):
        return 20000


def run_tshark_fields(
    file_path: str,
    display_filter: str | None,
    fields: list[str],
    extra_args: list[str] | None = None,
    timeout: int = 30,
    two_pass: bool = False,
) -> list[dict]:
    """
    Run tshark with field extraction and return parsed list of dicts.

    Builds: tshark -r <file> [-2] [-Y filter] -T fields -E separator=\t [-e field]... [extra_args]

    Args:
        file_path: Path to PCAP file (already validated by caller).
        display_filter: Optional display filter string (passed to -Y).
        fields: List of tshark field names (e.g. ["ip.src", "tcp.dstport"]).
        extra_args: Additional tshark arguments to append.
        timeout: Subprocess timeout in seconds.
        two_pass: If True, adds -2 flag for two-pass analysis.

    Returns:
        List of dicts keyed by field name, limited to MAX_PACKET_SLICE_RESULTS rows.
    """
    cmd = ["tshark", "-r", file_path]

    if two_pass:
        cmd.append("-2")

    if display_filter:
        cmd.extend(["-Y", display_filter])

    cmd.extend(["-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"])

    for field in fields:
        cmd.extend(["-e", field])

    if extra_args:
        cmd.extend(extra_args)

    stdout, stderr, returncode = run_command(cmd, timeout=timeout)

    if not stdout and returncode not in (0, 1):
        logger.warning(
            "run_tshark_fields: tshark returned %d: %s", returncode, stderr.strip()
        )
        return []

    max_results = get_max_results()
    return parse_fields_output(stdout, fields, max_rows=max_results)


def run_tshark_stat(
    file_path: str,
    stat_name: str,
    display_filter: str | None = None,
    timeout: int = 60,
) -> str:
    """
    Run tshark with a -z stat and return raw stdout.

    Builds: tshark -r <file> -q -z stat_name[,filter]

    Args:
        file_path: Path to PCAP file (already validated by caller).
        stat_name: The stat name (e.g. "conv,tcp", "io,stat,1.0").
        display_filter: Optional filter to append to stat name.
        timeout: Subprocess timeout in seconds.

    Returns:
        Raw stdout string from tshark.
    """
    stat_arg = stat_name
    if display_filter:
        stat_arg = f"{stat_name},{display_filter}"

    cmd = ["tshark", "-r", file_path, "-q", "-z", stat_arg]
    stdout, stderr, returncode = run_command(cmd, timeout=timeout)

    if not stdout and returncode not in (0, 1):
        logger.warning(
            "run_tshark_stat: tshark returned %d: %s", returncode, stderr.strip()
        )

    return stdout


def parse_fields_output(
    stdout: str,
    field_names: list[str],
    separator: str = "\t",
    max_rows: int | None = None,
) -> list[dict]:
    """
    Parse tshark -T fields output into a list of dicts.

    Args:
        stdout: Raw tshark output string.
        field_names: List of field names matching the -e flags used.
        separator: Column separator (default tab).
        max_rows: Maximum rows to return; None means no limit.

    Returns:
        List of dicts where keys are field_names. Missing columns become "".
    """
    if max_rows is None:
        max_rows = get_max_results()

    results = []
    for line in stdout.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue

        parts = line.split(separator)
        row = {}
        for i, name in enumerate(field_names):
            row[name] = parts[i].strip() if i < len(parts) else ""
        results.append(row)

        if len(results) >= max_rows:
            break

    return results


def packet_slice(
    file_path: str,
    display_filter: str | None = None,
    fields: list[str] | None = None,
    limit: int | None = None,
) -> dict:
    """
    Extract a slice of packets from a PCAP file with optional filter and field selection.

    This is the original packet_slice tool exposed to callers.

    Returns:
        {packets: list[dict], count: int, truncated: bool}
    """
    from tools.files import validate_pcap_path

    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "packets": [],
            "count": 0,
            "truncated": False,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    max_results = get_max_results()
    effective_limit = min(limit, max_results) if limit else max_results

    default_fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "frame.len",
    ]
    use_fields = fields if fields else default_fields

    rows = run_tshark_fields(
        file_path=normalized,
        display_filter=display_filter,
        fields=use_fields,
        timeout=30,
    )

    truncated = len(rows) >= effective_limit
    limited = rows[:effective_limit]

    return {
        "packets": limited,
        "count": len(limited),
        "truncated": truncated,
    }
