import os
import time
import json
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
DEFAULT_OLLAMA_URL = os.getenv("DEFAULT_OLLAMA_BASE_URL", "http://host.docker.internal:11434")
DEFAULT_OLLAMA_MODEL = os.getenv("DEFAULT_OLLAMA_MODEL", "gpt-oss:20b")


def init_session_state():
    defaults = {
        "ollama_ok": False,
        "ollama_base_url": DEFAULT_OLLAMA_URL,
        "ollama_model": DEFAULT_OLLAMA_MODEL,
        "selected_file": None,
        "scanned_files": [],
        "analysis_id": None,
        "analysis_complete": False,
        "analysis_report": None,
        "screen": "ollama_setup",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def backend_post(path: str, payload: dict) -> dict:
    url = f"{BACKEND_URL}{path}"
    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        return {"ok": True, "data": resp.json()}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"Cannot connect to backend at {BACKEND_URL}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Request timed out"}
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        return {"ok": False, "error": detail}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def backend_get(path: str) -> dict:
    url = f"{BACKEND_URL}{path}"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return {"ok": True, "data": resp.json()}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": f"Cannot connect to backend at {BACKEND_URL}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Request timed out"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def screen_ollama_setup():
    st.title("PCAP Analyzer")
    st.caption("Local Packet Analysis with Ollama")
    st.markdown("---")

    st.subheader("Step 1: Configure Ollama Connection")
    st.markdown(
        "This tool runs entirely locally. Your packet data never leaves your machine."
    )

    col1, col2 = st.columns(2)
    with col1:
        ollama_url = st.text_input(
            "Ollama Base URL",
            value=st.session_state.ollama_base_url,
            placeholder="http://host.docker.internal:11434",
            help="URL of your local Ollama instance",
        )
    with col2:
        ollama_model = st.text_input(
            "Model Name",
            value=st.session_state.ollama_model,
            placeholder="gpt-oss:20b",
            help="Name of the model to use for analysis",
        )

    if st.button("Test Ollama Connection", type="primary", use_container_width=True):
        with st.spinner("Testing connection..."):
            result = backend_post(
                "/api/ollama/test",
                {"base_url": ollama_url, "model": ollama_model},
            )
        if result["ok"]:
            data = result["data"]
            if data.get("success"):
                st.session_state.ollama_ok = True
                st.session_state.ollama_base_url = ollama_url
                st.session_state.ollama_model = ollama_model
                latency = data.get("latency_ms")
                model_name = data.get("model_name", ollama_model)
                msg = f"Connected successfully to **{model_name}**"
                if latency is not None:
                    msg += f" (latency: {latency:.0f} ms)"
                st.success(msg)
            else:
                st.session_state.ollama_ok = False
                reason = data.get("reason", "Unknown failure")
                st.error(f"Connection failed: {reason}")
        else:
            st.session_state.ollama_ok = False
            st.error(f"Backend error: {result['error']}")

    if st.session_state.ollama_ok:
        st.info(
            f"Ollama ready — model: `{st.session_state.ollama_model}` "
            f"at `{st.session_state.ollama_base_url}`"
        )
        if st.button(
            "Continue to Capture Selection →", type="secondary", use_container_width=True
        ):
            st.session_state.screen = "capture_selection"
            st.rerun()


def screen_capture_selection():
    st.title("PCAP Analyzer")
    st.caption("Local Packet Analysis with Ollama")
    st.markdown("---")

    st.subheader("Step 2: Select Capture File")

    with st.expander("Ollama Config", expanded=False):
        st.write(
            f"Model: `{st.session_state.ollama_model}` "
            f"at `{st.session_state.ollama_base_url}`"
        )
        if st.button("Change Ollama Settings"):
            st.session_state.screen = "ollama_setup"
            st.rerun()

    path_input = st.text_input(
        "PCAP Directory or File Path",
        value="/data/pcaps",
        help="Path inside the container (mounted from your host)",
    )

    if st.button("Scan Path", type="primary"):
        with st.spinner("Scanning for PCAP files..."):
            result = backend_post("/api/files/scan", {"path": path_input})
        if result["ok"]:
            data = result["data"]
            files = data.get("files", [])
            st.session_state.scanned_files = files
            if files:
                st.success(f"Found {data.get('count', len(files))} capture file(s)")
            else:
                st.warning("No .pcap or .pcapng files found at that path.")
        else:
            st.error(f"Scan failed: {result['error']}")
            st.session_state.scanned_files = []

    if st.session_state.scanned_files:
        st.markdown("**Discovered captures:**")
        selected = st.selectbox(
            "Choose a file",
            options=st.session_state.scanned_files,
            index=0,
        )

        if st.button("Select This File", type="secondary"):
            st.session_state.selected_file = selected
            st.success(f"Selected: `{selected}`")

    if st.session_state.selected_file:
        st.info(f"Selected file: `{st.session_state.selected_file}`")
        if st.button(
            "Continue to Investigation →", type="primary", use_container_width=True
        ):
            st.session_state.screen = "investigation_setup"
            st.rerun()


def screen_investigation_setup():
    st.title("PCAP Analyzer")
    st.caption("Local Packet Analysis with Ollama")
    st.markdown("---")

    st.subheader("Step 3: Define Investigation")

    st.info(f"File: `{st.session_state.selected_file}`")

    with st.expander("Change file or Ollama settings", expanded=False):
        if st.button("Back to File Selection"):
            st.session_state.screen = "capture_selection"
            st.rerun()
        if st.button("Back to Ollama Setup"):
            st.session_state.screen = "ollama_setup"
            st.rerun()

    goal = st.text_area(
        "Investigation Goal",
        height=100,
        placeholder=(
            "Examples:\n"
            "• Find slow HTTP transactions\n"
            "• Check who sent the TCP resets\n"
            "• Look for TLS alert failures\n"
            "• Help me understand whether backend slowness is visible"
        ),
        help="Describe what you want to investigate in plain language",
    )

    st.markdown("**Analysis Options:**")
    col1, col2 = st.columns(2)
    with col1:
        include_http = st.checkbox("Include HTTP analysis", value=True)
        include_tls = st.checkbox("Include TLS analysis", value=True)
    with col2:
        include_dns = st.checkbox("Include DNS analysis", value=False)
        deep_dive = st.checkbox("Deep dive mode", value=False, help="More thorough but slower")

    if st.button("Start Analysis", type="primary", use_container_width=True, disabled=not goal.strip()):
        if not goal.strip():
            st.warning("Please enter an investigation goal.")
        else:
            payload = {
                "ollama": {
                    "base_url": st.session_state.ollama_base_url,
                    "model": st.session_state.ollama_model,
                },
                "file_path": st.session_state.selected_file,
                "goal": goal.strip(),
                "options": {
                    "include_http": include_http,
                    "include_tls": include_tls,
                    "include_dns": include_dns,
                    "deep_dive": deep_dive,
                },
            }
            with st.spinner("Starting analysis..."):
                result = backend_post("/api/analysis/start", payload)
            if result["ok"]:
                data = result["data"]
                st.session_state.analysis_id = data.get("analysis_id")
                st.session_state.analysis_complete = False
                st.session_state.analysis_report = None
                st.session_state.screen = "results"
                st.rerun()
            else:
                st.error(f"Failed to start analysis: {result['error']}")


def screen_results():
    st.title("PCAP Analyzer")
    st.caption("Local Packet Analysis with Ollama")
    st.markdown("---")

    st.subheader("Step 4: Analysis Results")

    analysis_id = st.session_state.analysis_id
    if not analysis_id:
        st.error("No analysis in progress.")
        if st.button("Start New Analysis"):
            reset_session()
        return

    # Poll until complete
    if not st.session_state.analysis_complete:
        status_placeholder = st.empty()
        progress_placeholder = st.empty()

        with st.spinner("Analysis running..."):
            # Poll backend
            max_polls = 120  # 2 min with 1s sleep
            for _ in range(max_polls):
                result = backend_get(f"/api/analysis/{analysis_id}")
                if not result["ok"]:
                    status_placeholder.error(f"Error polling analysis: {result['error']}")
                    break

                data = result["data"]
                status = data.get("status", "unknown")
                progress = data.get("progress", "")

                if progress:
                    progress_placeholder.info(f"Progress: {progress}")

                if status == "complete":
                    st.session_state.analysis_complete = True
                    st.session_state.analysis_report = data.get("report")
                    break
                elif status == "failed":
                    st.session_state.analysis_complete = True
                    status_placeholder.error(f"Analysis failed: {progress}")
                    break
                elif status == "running":
                    time.sleep(2)
                else:
                    status_placeholder.warning(f"Unknown status: {status}")
                    time.sleep(2)
            else:
                status_placeholder.error("Analysis timed out waiting for results.")

        if st.session_state.analysis_complete:
            st.rerun()
        return

    # Render completed report
    report = st.session_state.analysis_report
    if not report:
        st.error("Analysis complete but no report available.")
        if st.button("Start New Analysis"):
            reset_session()
        return

    render_report(report)

    # Export button
    md_content = build_markdown_report(report)
    st.download_button(
        label="Export Report as Markdown",
        data=md_content,
        file_name=f"pcap_analysis_{analysis_id[:8]}.md",
        mime="text/markdown",
        use_container_width=True,
    )

    st.markdown("---")
    if st.button("Start New Analysis", use_container_width=True):
        reset_session()


def render_report(report: dict):
    # Summary
    summary = report.get("summary", "")
    if summary:
        st.markdown("### Summary")
        st.markdown(summary)

    # Findings
    findings = report.get("findings", [])
    if findings:
        st.markdown("### Findings")
        for i, finding in enumerate(findings, 1):
            confidence = finding.get("confidence", "unknown").lower()
            badge_color = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢",
            }.get(confidence, "⚪")

            with st.expander(
                f"{badge_color} [{confidence.upper()}] {finding.get('title', f'Finding {i}')}",
                expanded=True,
            ):
                st.markdown(finding.get("explanation", ""))
                evidence = finding.get("evidence", {})
                if evidence:
                    st.markdown("**Evidence:**")
                    stream_ids = evidence.get("stream_ids", [])
                    pkt_nums = evidence.get("packet_numbers", [])
                    ws_filter = evidence.get("filter", "")
                    if stream_ids:
                        st.markdown(f"- Stream IDs: {stream_ids}")
                    if pkt_nums:
                        st.markdown(f"- Packet numbers: {pkt_nums}")
                    if ws_filter:
                        st.code(ws_filter, language="text")

    # Suspicious Streams
    suspicious = report.get("suspicious_streams", [])
    if suspicious:
        st.markdown("### Suspicious Streams")
        for stream in suspicious:
            st.json(stream)

    # Open Questions
    questions = report.get("open_questions", [])
    if questions:
        st.markdown("### Open Questions")
        for q in questions:
            st.markdown(f"- {q}")

    # Next Steps
    next_steps = report.get("next_steps", [])
    if next_steps:
        st.markdown("### Next Steps")
        for step in next_steps:
            st.markdown(f"- {step}")

    # Wireshark Filters
    all_filters = []
    for finding in report.get("findings", []):
        f = finding.get("evidence", {}).get("filter", "")
        if f and f not in all_filters:
            all_filters.append(f)

    if all_filters:
        st.markdown("### Wireshark Filters")
        for f in all_filters:
            st.code(f, language="text")


def build_markdown_report(report: dict) -> str:
    lines = ["# PCAP Analysis Report", ""]

    summary = report.get("summary", "")
    if summary:
        lines += ["## Summary", "", summary, ""]

    findings = report.get("findings", [])
    if findings:
        lines += ["## Findings", ""]
        for i, finding in enumerate(findings, 1):
            confidence = finding.get("confidence", "unknown").upper()
            title = finding.get("title", f"Finding {i}")
            lines += [f"### [{confidence}] {title}", ""]
            lines += [finding.get("explanation", ""), ""]
            evidence = finding.get("evidence", {})
            if evidence:
                lines += ["**Evidence:**", ""]
                stream_ids = evidence.get("stream_ids", [])
                pkt_nums = evidence.get("packet_numbers", [])
                ws_filter = evidence.get("filter", "")
                if stream_ids:
                    lines.append(f"- Stream IDs: {stream_ids}")
                if pkt_nums:
                    lines.append(f"- Packet numbers: {pkt_nums}")
                if ws_filter:
                    lines += ["", f"```\n{ws_filter}\n```", ""]

    suspicious = report.get("suspicious_streams", [])
    if suspicious:
        lines += ["## Suspicious Streams", ""]
        for s in suspicious:
            lines.append(f"- {json.dumps(s)}")
        lines.append("")

    questions = report.get("open_questions", [])
    if questions:
        lines += ["## Open Questions", ""]
        for q in questions:
            lines.append(f"- {q}")
        lines.append("")

    next_steps = report.get("next_steps", [])
    if next_steps:
        lines += ["## Next Steps", ""]
        for step in next_steps:
            lines.append(f"- {step}")
        lines.append("")

    return "\n".join(lines)


def reset_session():
    keys_to_clear = [
        "ollama_ok", "selected_file", "scanned_files",
        "analysis_id", "analysis_complete", "analysis_report",
    ]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    st.session_state.screen = "ollama_setup"
    st.rerun()


def main():
    st.set_page_config(
        page_title="PCAP Analyzer",
        page_icon="🔬",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    init_session_state()

    screen = st.session_state.get("screen", "ollama_setup")

    if screen == "ollama_setup":
        screen_ollama_setup()
    elif screen == "capture_selection":
        if not st.session_state.ollama_ok:
            st.session_state.screen = "ollama_setup"
            st.rerun()
        else:
            screen_capture_selection()
    elif screen == "investigation_setup":
        if not st.session_state.ollama_ok:
            st.session_state.screen = "ollama_setup"
            st.rerun()
        elif not st.session_state.selected_file:
            st.session_state.screen = "capture_selection"
            st.rerun()
        else:
            screen_investigation_setup()
    elif screen == "results":
        if not st.session_state.analysis_id:
            st.session_state.screen = "investigation_setup"
            st.rerun()
        else:
            screen_results()
    else:
        st.error(f"Unknown screen: {screen}")
        st.session_state.screen = "ollama_setup"
        st.rerun()


if __name__ == "__main__":
    main()
