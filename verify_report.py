import json
import sys

from analyzer.evidence.verify import verify_evidence


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: python verify_report.py <report.json>"
        )
        return 1

    report_path = sys.argv[1]

    try:
        with open(
            report_path,
            "r",
            encoding="utf-8",
        ) as f:
            report = json.load(f)

    except FileNotFoundError:
        print(
            f"ERROR: report not found: {report_path}"
        )
        return 1

    except json.JSONDecodeError as exc:
        print(
            f"ERROR: invalid JSON: {exc}"
        )
        return 1

    artifacts = report.get(
        "evidence",
        [],
    )

    manifest = report.get(
        "evidence_manifest"
    )

    findings = report.get(
        "findings",
        [],
    )

    result = verify_evidence(
        artifacts=artifacts,
        manifest=manifest,
        findings=findings,
    )

    print(
        "Overall valid:",
        result["valid"],
    )

    print(
        "Artifacts:",
        result["artifact_count"],
    )

    print(
        "Verified:",
        result["verified_count"],
    )

    print(
        "Failed:",
        result["failed_count"],
    )

    provenance = result["provenance"]

    print(
        "Artifact provenance:",
        provenance["valid"],
    )

    print(
        "Artifact provenance errors:",
        provenance["error_count"],
    )

    finding_identity = result[
        "finding_identity"
    ]

    print(
        "Finding identity:",
        finding_identity["valid"],
    )

    print(
        "Finding identity errors:",
        finding_identity["error_count"],
    )

    finding_provenance = result[
        "finding_provenance"
    ]

    print(
        "Finding provenance:",
        finding_provenance["valid"],
    )

    print(
        "Finding provenance errors:",
        finding_provenance["error_count"],
    )

    manifest_result = result[
        "manifest"
    ]

    if manifest_result is not None:
        print(
            "Manifest valid:",
            manifest_result["valid"],
        )

    if not result["valid"]:
        print()
        print("Verification errors:")

        for section_name in [
            "provenance",
            "finding_identity",
            "finding_provenance",
        ]:
            section = result.get(
                section_name
            )

            if not section:
                continue

            for error in section.get(
                "errors",
                [],
            ):
                print(
                    f"- {section_name}: "
                    f"{error}"
                )

        if manifest_result:
            if not manifest_result[
                "valid"
            ]:
                print(
                    "- manifest:",
                    manifest_result,
                )

        for artifact_result in result[
            "artifacts"
        ]:
            if not artifact_result[
                "valid"
            ]:
                print(
                    "- artifact:",
                    artifact_result,
                )

        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
