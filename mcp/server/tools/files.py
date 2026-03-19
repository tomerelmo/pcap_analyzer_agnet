import os
import glob
import logging
from tools.helpers import run_command

logger = logging.getLogger(__name__)

# Allowed roots from env, colon-separated
ALLOWED_ROOTS: list[str] = [
    r.strip()
    for r in os.environ.get("ALLOWED_PCAP_ROOTS", "/data/pcaps").split(":")
    if r.strip()
]

PCAP_EXTENSIONS = {".pcap", ".pcapng"}


def validate_pcap_path(path: str) -> dict:
    """
    Validate that a path is within allowed roots, exists, and has the right extension.

    Returns a dict with: valid, reason, normalized_path, type ("file"|"directory"|None)
    """
    if not path:
        return {
            "valid": False,
            "reason": "Path is empty",
            "normalized_path": "",
            "type": None,
        }

    # Normalize to resolve symlinks and .. traversal
    normalized = os.path.realpath(path)

    # Check allowed roots
    in_allowed_root = any(
        normalized.startswith(os.path.realpath(root) + os.sep)
        or normalized == os.path.realpath(root)
        for root in ALLOWED_ROOTS
    )
    if not in_allowed_root:
        allowed_str = ", ".join(ALLOWED_ROOTS)
        return {
            "valid": False,
            "reason": (
                f"Path '{normalized}' is outside allowed roots: {allowed_str}. "
                "Make sure your PCAP files are in the mounted directory."
            ),
            "normalized_path": normalized,
            "type": None,
        }

    # Check existence
    if not os.path.exists(normalized):
        return {
            "valid": False,
            "reason": f"Path does not exist: {normalized}",
            "normalized_path": normalized,
            "type": None,
        }

    # Determine type
    if os.path.isdir(normalized):
        return {
            "valid": True,
            "reason": "Directory is accessible",
            "normalized_path": normalized,
            "type": "directory",
        }

    if os.path.isfile(normalized):
        ext = os.path.splitext(normalized)[1].lower()
        if ext not in PCAP_EXTENSIONS:
            return {
                "valid": False,
                "reason": (
                    f"File extension '{ext}' is not supported. "
                    f"Only {', '.join(PCAP_EXTENSIONS)} files are allowed."
                ),
                "normalized_path": normalized,
                "type": "file",
            }
        return {
            "valid": True,
            "reason": "File is accessible",
            "normalized_path": normalized,
            "type": "file",
        }

    # Symlink or other
    return {
        "valid": False,
        "reason": f"Path exists but is not a regular file or directory: {normalized}",
        "normalized_path": normalized,
        "type": None,
    }


def list_pcaps(path: str) -> dict:
    """
    List PCAP files at a path (top-level only for v1).

    Returns: {files: [...], count: int, path: str}
    """
    validation = validate_pcap_path(path)
    if not validation["valid"]:
        return {
            "files": [],
            "count": 0,
            "path": path,
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]
    path_type = validation["type"]

    if path_type == "file":
        return {
            "files": [normalized],
            "count": 1,
            "path": normalized,
        }

    # Directory: list top-level pcap/pcapng files only
    found = []
    for ext in PCAP_EXTENSIONS:
        # Top-level only (not recursive) for v1
        pattern = os.path.join(normalized, f"*{ext}")
        found.extend(glob.glob(pattern))

    found.sort()

    return {
        "files": found,
        "count": len(found),
        "path": normalized,
    }


def describe_capture(file_path: str) -> dict:
    """
    Run capinfos on a PCAP file and return structured info.

    Returns: {file: str, info: dict, raw: str} or {file: str, error: str, raw: str}
    """
    validation = validate_pcap_path(file_path)
    if not validation["valid"]:
        return {
            "file": file_path,
            "info": {},
            "raw": "",
            "error": validation["reason"],
        }

    normalized = validation["normalized_path"]

    # capinfos -M gives machine-readable output, -T is tab-separated
    stdout, stderr, returncode = run_command(
        ["capinfos", "-M", "-T", normalized],
        timeout=30,
    )

    raw = stdout or stderr

    if returncode != 0:
        return {
            "file": normalized,
            "info": {},
            "raw": raw,
            "error": f"capinfos exited with code {returncode}: {stderr.strip()}",
        }

    # Parse tab-separated key\tvalue lines
    info = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # capinfos -T -M outputs "Key\tValue" pairs
        if "\t" in line:
            key, _, value = line.partition("\t")
            info[key.strip()] = value.strip()
        elif ":" in line:
            # Fallback: colon-separated
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()

    return {
        "file": normalized,
        "info": info,
        "raw": stdout,
    }
