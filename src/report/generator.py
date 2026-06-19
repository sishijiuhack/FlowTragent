"""Report generation for FlowTragent."""

from __future__ import annotations

import json
from pathlib import Path


def write_report(analysis: dict, output_dir: str | Path = "reports") -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = analysis["generated_at"].replace(":", "").replace(".", "").replace("Z", "Z")
    md_path = output / f"flowtragent_report_{stamp}.md"
    json_path = output / f"flowtragent_report_{stamp}.json"

    lines = [
        "# FlowTragent Attack Trace Report",
        "",
        f"- Generated at: `{analysis['generated_at']}`",
        f"- Source file: `{analysis.get('source_file') or 'payload input'}`",
        f"- Parsed CSV: `{analysis.get('csv_file') or 'N/A'}`",
        f"- Payload count: `{analysis.get('payload_count', 0)}`",
        "",
        "## Attack Assessment",
    ]
    for attack_type in analysis.get("attack_types", []):
        lines.append(f"- {attack_type}")

    lines.extend(["", "## Top CVE Candidates"])
    top_cves = analysis.get("top_cves", [])
    if top_cves:
        lines.extend(["| CVE | Score | Evidence |", "| --- | ---: | --- |"])
        for item in top_cves:
            evidence = str(item.get("evidence", "")).replace("|", "\\|")[:160]
            lines.append(f"| {item.get('cve')} | {item.get('score')} | `{evidence}` |")
    else:
        lines.append("- No CVE candidate passed retrieval.")

    lines.extend(["", "## Timeline"])
    for item in analysis.get("timeline", []):
        lines.append(f"{item.get('step')}. {item.get('event')}")

    lines.extend(["", "## Recommendations"])
    for item in analysis.get("recommendations", []):
        lines.append(f"- {item}")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    return md_path

