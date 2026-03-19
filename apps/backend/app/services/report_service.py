from app.models.responses import AnalysisReport


def format_as_markdown(report: AnalysisReport) -> str:
    """Format an AnalysisReport as a clean markdown document."""
    lines = ["# PCAP Analysis Report", ""]

    # Summary
    if report.summary:
        lines += ["## Summary", "", report.summary, ""]

    # Findings
    if report.findings:
        lines += ["## Findings", ""]
        for i, finding in enumerate(report.findings, 1):
            confidence = finding.confidence.upper()
            lines += [f"### {i}. [{confidence}] {finding.title}", ""]
            lines += [finding.explanation, ""]
            ev = finding.evidence
            has_evidence = ev.stream_ids or ev.packet_numbers or ev.filter
            if has_evidence:
                lines += ["**Evidence:**", ""]
                if ev.stream_ids:
                    lines.append(f"- Stream IDs: {ev.stream_ids}")
                if ev.packet_numbers:
                    lines.append(f"- Packet numbers: {ev.packet_numbers}")
                if ev.filter:
                    lines += ["", f"Wireshark filter:", "", f"```", ev.filter, "```", ""]
                else:
                    lines.append("")

    # Suspicious Streams
    if report.suspicious_streams:
        lines += ["## Suspicious Streams", ""]
        for stream in report.suspicious_streams:
            src = stream.get("src", "?")
            dst = stream.get("dst", "?")
            reason = stream.get("reason", "")
            entry = f"- `{src}` → `{dst}`"
            if reason:
                entry += f": {reason}"
            lines.append(entry)
        lines.append("")

    # Open Questions
    if report.open_questions:
        lines += ["## Open Questions", ""]
        for q in report.open_questions:
            lines.append(f"- {q}")
        lines.append("")

    # Next Steps
    if report.next_steps:
        lines += ["## Next Steps", ""]
        for step in report.next_steps:
            lines.append(f"- {step}")
        lines.append("")

    # All Wireshark Filters consolidated
    all_filters = [
        f.evidence.filter
        for f in report.findings
        if f.evidence.filter
    ]
    if all_filters:
        lines += ["## Wireshark Filters", ""]
        lines.append("Copy-paste these into Wireshark's display filter bar:")
        lines.append("")
        for f in all_filters:
            lines.append(f"```")
            lines.append(f)
            lines.append("```")
            lines.append("")

    return "\n".join(lines)
