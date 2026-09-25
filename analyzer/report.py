from __future__ import annotations

from typing import Any


def _status(value: Any, *, status_key: str = "status") -> str:
    if isinstance(value, dict):
        status = value.get(status_key)

        if isinstance(status, list):
            return ", ".join(str(item) for item in status)

        if status is not None:
            return str(status)

    return "unknown"

def _available(value: Any) -> str:
    if isinstance(value, dict):
        available = value.get("available")
        if available is True:
            return "yes"
        if available is False:
            return "no"
    return "unknown"


def _finding_line(finding: dict) -> str:
    finding_id = finding.get("finding_id", "unknown")
    category = finding.get("category", "unknown")
    name = finding.get("name", "unknown")
    confidence = finding.get("confidence", "unknown")
    finding_type = finding.get("finding_type", "unknown")
    description = finding.get("description")

    line = (
        f"- [{finding_id}] "
        f"{category}: {name} "
        f"(type={finding_type}, confidence={confidence})"
    )

    if description:
        line += f"\n  {description}"

    return line


def render_human_report(report: dict) -> str:
    domain = report.get("domain", "unknown")
    case_id = report.get("case_id", "unknown")
    run_id = report.get("run_id", "unknown")
    tool = report.get(
    "tool",
    "ShadowNode Domain Intelligence Analyzer",
)
    tool_version = report.get("tool_version", "unknown")

    started = report.get(
        "collection_started_at",
        "unknown",
    )
    completed = report.get(
        "collection_completed_at",
        "unknown",
    )

    findings = report.get("findings", [])
    evidence = report.get("evidence", [])
    manifest = report.get("evidence_manifest", {})

    lines: list[str] = []

    lines.append(
    "SHADOWNODE DOMAIN INTELLIGENCE ANALYZER (SDIA)"
)
    lines.append("DOMAIN INVESTIGATION REPORT")
    lines.append("=" * 80)
    lines.append("")

    lines.append("INVESTIGATION")
    lines.append("-" * 80)
    lines.append(f"Domain: {domain}")
    lines.append(f"Case ID: {case_id}")
    lines.append(f"Run ID: {run_id}")
    lines.append(f"Tool: {tool} {tool_version}")
    lines.append(f"Collection started: {started}")
    lines.append(f"Collection completed: {completed}")
    lines.append("")

    lines.append("COLLECTOR STATUS")
    lines.append("-" * 80)

    collectors = (
        ("RDAP", report.get("rdap"), "lookup_status"),
        ("DNS", report.get("dns"), "status"),
        ("IP", report.get("ip"), "status"),
        ("ASN", report.get("asn"), "status"),
        ("HTTP", report.get("http"), "status"),
        ("TLS", report.get("tls"), "status"),
        (
            "Certificate Transparency",
            report.get("ct"),
            "status",
        ),
    )

    for name, value, status_key in collectors:
        lines.append(
            f"- {name}: "
            f"status={_status(value, status_key=status_key)}, "
            f"available={_available(value)}"
        )

    lines.append("")

    lines.append("FINDINGS")
    lines.append("-" * 80)

    if findings:
        for finding in findings:
            lines.append(_finding_line(finding))
    else:
        lines.append("- No findings were recorded.")

    lines.append("")

    lines.append("EVIDENCE")
    lines.append("-" * 80)
    lines.append(f"Artifacts: {len(evidence)}")

    verified = manifest.get("sha256")
    if verified:
        lines.append(
            f"Manifest SHA-256: {verified}"
        )

    for artifact in evidence:
        artifact_id = artifact.get(
            "artifact_id",
            "unknown",
        )
        artifact_type = artifact.get(
            "artifact_type",
            "unknown",
        )
        classification = artifact.get(
            "classification",
            "unknown",
        )
        sha256 = artifact.get(
            "sha256",
            "unknown",
        )

        lines.append(
            f"- {artifact_id} | "
            f"type={artifact_type} | "
            f"classification={classification}"
        )
        lines.append(
            f"  SHA-256: {sha256}"
        )

    lines.append("")

    lines.append("INTERPRETATION")
    lines.append("-" * 80)
    lines.append(
        "Findings represent observations or analytical "
        "correlations derived from the collected evidence."
    )
    lines.append(
        "Correlations do not, by themselves, establish "
        "ownership, administrative control, or organizational "
        "relationships."
    )
    lines.append(
        "Certificate Transparency observations are "
        "certificate-associated historical observations and "
        "do not by themselves establish that a hostname is "
        "currently active."
    )

    lines.append("")

    lines.append("END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)
