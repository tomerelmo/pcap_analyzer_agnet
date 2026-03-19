import json
import logging
from typing import Optional

from app.models.requests import AnalysisStartRequest
from app.models.responses import AnalysisReport, Finding, Evidence
from app.services import session_service, mcp_client, ollama_service

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a careful network packet analyst. "
    "Base all findings on the provided tool outputs only. "
    "Never invent packet details. "
    "If the evidence is insufficient to make a claim, say so explicitly. "
    "Distinguish between confirmed facts and interpretations."
)


def _truncate(text: str, max_chars: int = 8000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def _build_analysis_prompt(
    goal: str,
    capture_info: dict,
    conversations: dict,
    resets: dict,
    options: dict,
) -> str:
    sections = [
        f"## Investigation Goal\n{goal}",
    ]

    # Capture metadata
    info = capture_info.get("info", {})
    raw_info = capture_info.get("raw", "")
    if info:
        meta_lines = "\n".join(f"  {k}: {v}" for k, v in info.items())
        sections.append(f"## Capture Metadata\n{meta_lines}")
    elif raw_info:
        sections.append(f"## Capture Metadata\n{_truncate(raw_info, 2000)}")
    else:
        err = capture_info.get("error", "Unknown error")
        sections.append(f"## Capture Metadata\nError reading metadata: {err}")

    # Conversations
    conv_list = conversations.get("conversations", [])
    conv_count = conversations.get("count", len(conv_list))
    if conv_list:
        conv_lines = [f"Total TCP conversations: {conv_count}"]
        for c in conv_list[:50]:
            conv_lines.append(
                f"  {c.get('src','?')} <-> {c.get('dst','?')} | "
                f"pkts={c.get('packets','?')} bytes={c.get('bytes','?')} "
                f"dur={c.get('duration','?')}"
            )
        sections.append("## TCP Conversations\n" + "\n".join(conv_lines))
    else:
        raw_conv = conversations.get("raw", "")
        if raw_conv:
            sections.append(f"## TCP Conversations (raw)\n{_truncate(raw_conv, 3000)}")
        else:
            sections.append("## TCP Conversations\nNo conversation data available.")

    # Resets
    reset_list = resets.get("resets", [])
    reset_count = resets.get("count", len(reset_list))
    truncated = resets.get("truncated", False)
    if reset_list:
        reset_lines = [f"TCP resets found: {reset_count}" + (" (truncated)" if truncated else "")]
        for r in reset_list[:100]:
            reset_lines.append(
                f"  frame={r.get('frame_number','?')} "
                f"time={r.get('time_relative','?')}s "
                f"{r.get('ip_src','?')}:{r.get('tcp_srcport','?')} -> "
                f"{r.get('ip_dst','?')}:{r.get('tcp_dstport','?')}"
            )
        sections.append("## TCP Resets\n" + "\n".join(reset_lines))
    else:
        sections.append("## TCP Resets\nNo TCP reset packets found.")

    # Analysis options context
    opts_lines = []
    if options.get("include_http"):
        opts_lines.append("- HTTP analysis requested")
    if options.get("include_tls"):
        opts_lines.append("- TLS analysis requested")
    if options.get("include_dns"):
        opts_lines.append("- DNS analysis requested")
    if options.get("deep_dive"):
        opts_lines.append("- Deep dive mode enabled")
    if opts_lines:
        sections.append("## Analysis Options\n" + "\n".join(opts_lines))

    # Schema instruction
    schema_example = json.dumps(
        {
            "summary": "One paragraph describing the capture and key findings.",
            "findings": [
                {
                    "title": "Short title",
                    "confidence": "high|medium|low",
                    "explanation": "Detailed explanation based on evidence.",
                    "evidence": {
                        "stream_ids": [1, 2],
                        "packet_numbers": [100, 200],
                        "filter": "tcp.flags.reset == 1",
                    },
                }
            ],
            "suspicious_streams": [
                {"src": "10.0.0.1:1234", "dst": "10.0.0.2:80", "reason": "why flagged"}
            ],
            "open_questions": ["What triggered the resets?"],
            "next_steps": ["Apply filter tcp.flags.reset==1 in Wireshark and inspect."],
        },
        indent=2,
    )

    sections.append(
        f"## Required Output Format\n"
        f"Respond with ONLY valid JSON matching this schema. No markdown, no prose outside the JSON:\n"
        f"{schema_example}"
    )

    return "\n\n".join(sections)


def _parse_llm_response(response_text: str, goal: str) -> AnalysisReport:
    """Parse LLM JSON response into AnalysisReport, with fallback."""
    # Try to extract JSON from the response
    text = response_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last fence lines
        inner = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            elif line.startswith("```") and in_block:
                break
            elif in_block:
                inner.append(line)
        text = "\n".join(inner).strip()

    try:
        data = json.loads(text)
        findings = []
        for f in data.get("findings", []):
            ev_data = f.get("evidence", {})
            evidence = Evidence(
                stream_ids=ev_data.get("stream_ids", []),
                packet_numbers=ev_data.get("packet_numbers", []),
                filter=ev_data.get("filter"),
            )
            findings.append(
                Finding(
                    title=f.get("title", "Unnamed finding"),
                    confidence=f.get("confidence", "medium"),
                    explanation=f.get("explanation", ""),
                    evidence=evidence,
                )
            )
        return AnalysisReport(
            summary=data.get("summary", "Analysis complete."),
            findings=findings,
            suspicious_streams=data.get("suspicious_streams", []),
            open_questions=data.get("open_questions", []),
            next_steps=data.get("next_steps", []),
        )
    except json.JSONDecodeError:
        logger.warning("LLM response was not valid JSON, using fallback text report")
        return AnalysisReport(
            summary=(
                f"Analysis complete for goal: {goal}\n\n"
                f"The model returned a non-JSON response. Raw output:\n\n"
                f"{response_text[:3000]}"
            ),
            findings=[],
            suspicious_streams=[],
            open_questions=["Could not parse structured findings from LLM response."],
            next_steps=["Review the raw summary above for insights."],
        )


async def run_analysis(session_id: str, request: AnalysisStartRequest) -> None:
    """
    Core staged analysis function. Runs as a background task.
    Mutates session state throughout execution.
    """
    file_path = request.file_path
    ollama_base_url = request.ollama.base_url
    ollama_model = request.ollama.model
    goal = request.goal
    options = request.options.model_dump()

    def update(status: Optional[str] = None, progress: Optional[str] = None, report: Optional[dict] = None):
        session_service.update_session(session_id, status=status, progress=progress, report=report)

    try:
        # Stage 1: Validate file
        update(status="running", progress="Validating file...")
        validation = await mcp_client.validate_pcap_path(file_path)
        if not validation.get("valid"):
            reason = validation.get("reason", "File validation failed")
            update(status="failed", progress=f"File invalid: {reason}")
            return

        # Stage 2: Capture metadata
        update(progress="Reading capture metadata...")
        capture_info = await mcp_client.describe_capture(file_path)

        # Stage 3: TCP conversations
        update(progress="Analyzing TCP conversations...")
        conversations = await mcp_client.get_conversations(file_path)

        # Stage 4: TCP resets
        update(progress="Detecting TCP resets...")
        resets = await mcp_client.find_resets(file_path)

        # Stage 5: Build prompt and call Ollama
        update(progress="Asking Ollama for analysis...")
        prompt = _build_analysis_prompt(goal, capture_info, conversations, resets, options)
        logger.info(
            "Sending analysis prompt to Ollama (model=%s, prompt_len=%d)",
            ollama_model,
            len(prompt),
        )

        llm_response = await ollama_service.generate(
            base_url=ollama_base_url,
            model=ollama_model,
            prompt=prompt,
            system=SYSTEM_PROMPT,
        )

        # Stage 6: Parse and store report
        update(progress="Parsing results...")
        report = _parse_llm_response(llm_response, goal)

        update(
            status="complete",
            progress="Analysis complete",
            report=report.model_dump(),
        )
        logger.info("Analysis %s completed successfully", session_id)

    except RuntimeError as e:
        logger.error("Analysis %s failed: %s", session_id, e)
        update(status="failed", progress=str(e))
    except Exception as e:
        logger.exception("Unexpected error in analysis %s", session_id)
        update(status="failed", progress=f"Unexpected error: {e}")
