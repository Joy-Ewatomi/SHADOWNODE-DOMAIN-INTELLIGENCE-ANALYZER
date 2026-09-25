from .hashing import sha256_json


def verify_artifact(artifact: dict) -> dict:
    """
    Recalculate an evidence artifact's SHA-256 and compare it
    with the recorded digest.
    """

    expected = artifact.get("sha256")

    actual = sha256_json(
        artifact.get("data")
    )

    return {
        "artifact_id": artifact.get("artifact_id"),
        "expected_sha256": expected,
        "actual_sha256": actual,
        "valid": expected == actual,
    }


def verify_manifest(manifest: dict) -> dict:
    """
    Recalculate the manifest SHA-256 and compare it with the
    recorded digest.
    """

    expected = manifest.get("sha256")

    payload = {
        "case_id": manifest.get("case_id"),
        "run_id": manifest.get("run_id"),
        "created_at": manifest.get("created_at"),
        "finalized_at": manifest.get("finalized_at"),
        "sealed": manifest.get("sealed", False),
        "artifact_count": manifest.get(
            "artifact_count",
            len(manifest.get("artifacts", [])),
        ),
        "artifacts": manifest.get("artifacts", []),
    }

    actual = sha256_json(payload)

    return {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "valid": expected == actual,
    }


def verify_provenance(
    artifacts: list[dict],
) -> dict:
    """
    Verify relationships between evidence artifacts.

    Checks:

    1. Every artifact has a unique artifact ID.
    2. Every parent artifact reference exists.
    3. An artifact cannot reference itself as a parent.
    4. Derived artifacts must have at least one parent.
    5. Observed artifacts should not have parents.
    """

    artifact_ids = [
        artifact.get("artifact_id")
        for artifact in artifacts
    ]

    duplicate_ids = sorted({
        artifact_id
        for artifact_id in artifact_ids
        if artifact_id is not None
        and artifact_ids.count(artifact_id) > 1
    })

    known_ids = {
        artifact_id
        for artifact_id in artifact_ids
        if artifact_id is not None
    }

    errors = []

    for artifact in artifacts:
        artifact_id = artifact.get(
            "artifact_id"
        )

        classification = artifact.get(
            "classification",
            "observed",
        )

        parents = artifact.get(
            "parent_artifacts",
            [],
        )

        if not isinstance(parents, list):
            errors.append({
                "artifact_id": artifact_id,
                "error": (
                    "parent_artifacts must be a list"
                ),
            })
            continue

        if artifact_id is None:
            errors.append({
                "artifact_id": None,
                "error": "missing artifact_id",
            })

        if artifact_id in duplicate_ids:
            errors.append({
                "artifact_id": artifact_id,
                "error": "duplicate artifact_id",
            })

        if classification == "derived" and not parents:
            errors.append({
                "artifact_id": artifact_id,
                "error": (
                    "derived artifact has no "
                    "parent artifacts"
                ),
            })

        if classification == "observed" and parents:
            errors.append({
                "artifact_id": artifact_id,
                "error": (
                    "observed artifact has parent "
                    "artifacts"
                ),
            })

        for parent_id in parents:
            if parent_id == artifact_id:
                errors.append({
                    "artifact_id": artifact_id,
                    "parent_artifact": parent_id,
                    "error": (
                        "artifact cannot reference "
                        "itself as a parent"
                    ),
                })

            elif parent_id not in known_ids:
                errors.append({
                    "artifact_id": artifact_id,
                    "parent_artifact": parent_id,
                    "error": (
                        "parent artifact does not exist"
                    ),
                })

    return {
        "valid": not errors,
        "artifact_count": len(artifacts),
        "unique_artifact_count": len(
            known_ids
        ),
        "duplicate_artifact_ids": duplicate_ids,
        "error_count": len(errors),
        "errors": errors,
    }


def verify_finding_identity(
    findings: list[dict],
) -> dict:
    """
    Verify finding identifiers.

    Checks:

    1. Every finding has a finding_id.
    2. Every finding_id is unique.
    """

    finding_ids = [
        finding.get("finding_id")
        for finding in findings
    ]

    duplicate_ids = sorted({
        finding_id
        for finding_id in finding_ids
        if finding_id is not None
        and finding_ids.count(finding_id) > 1
    })

    errors = []

    for finding_id in finding_ids:
        if finding_id is None:
            errors.append({
                "finding_id": None,
                "error": "missing finding_id",
            })

    for finding_id in duplicate_ids:
        errors.append({
            "finding_id": finding_id,
            "error": "duplicate finding_id",
        })

    unique_ids = {
        finding_id
        for finding_id in finding_ids
        if finding_id is not None
    }

    return {
        "valid": not errors,
        "finding_count": len(findings),
        "unique_finding_count": len(unique_ids),
        "duplicate_finding_ids": duplicate_ids,
        "error_count": len(errors),
        "errors": errors,
    }


def verify_finding_provenance(
    findings: list[dict],
    artifacts: list[dict],
) -> dict:
    """
    Verify that every evidence artifact referenced by a finding
    actually exists in the preserved evidence collection.

    Also requires every finding to have at least one supporting
    evidence artifact.
    """

    known_ids = {
        artifact.get("artifact_id")
        for artifact in artifacts
        if artifact.get("artifact_id")
    }

    errors = []
    referenced_ids = set()

    for finding in findings:
        finding_id = finding.get(
            "finding_id",
            "<unnamed finding>",
        )

        artifact_ids = finding.get(
            "evidence_artifacts",
            [],
        )

        if not isinstance(
            artifact_ids,
            list,
        ):
            errors.append({
                "finding_id": finding_id,
                "error": (
                    "evidence_artifacts must be "
                    "a list"
                ),
            })
            continue

        if not artifact_ids:
            errors.append({
                "finding_id": finding_id,
                "error": (
                    "finding has no supporting "
                    "evidence artifacts"
                ),
            })

        for artifact_id in artifact_ids:
            referenced_ids.add(
                artifact_id
            )

            if artifact_id not in known_ids:
                errors.append({
                    "finding_id": finding_id,
                    "artifact_id": artifact_id,
                    "error": (
                        "referenced evidence artifact "
                        "does not exist"
                    ),
                })

    return {
        "valid": not errors,
        "finding_count": len(findings),
        "referenced_artifact_count": len(
            referenced_ids
        ),
        "error_count": len(errors),
        "errors": errors,
    }


def verify_evidence(
    artifacts: list[dict],
    manifest: dict | None = None,
    findings: list[dict] | None = None,
) -> dict:
    """
    Verify evidence artifact integrity, artifact provenance,
    finding identity, finding provenance, and the collection
    manifest.
    """

    artifact_results = [
        verify_artifact(artifact)
        for artifact in artifacts
    ]

    artifacts_valid = all(
        result["valid"]
        for result in artifact_results
    )

    provenance_result = verify_provenance(
        artifacts
    )

    provenance_valid = provenance_result[
        "valid"
    ]

    finding_identity_result = None
    finding_identity_valid = True

    finding_provenance_result = None
    finding_provenance_valid = True

    if findings is not None:
        finding_identity_result = (
            verify_finding_identity(
                findings=findings,
            )
        )

        finding_identity_valid = (
            finding_identity_result["valid"]
        )

        finding_provenance_result = (
            verify_finding_provenance(
                findings=findings,
                artifacts=artifacts,
            )
        )

        finding_provenance_valid = (
            finding_provenance_result["valid"]
        )

    manifest_result = None
    manifest_valid = True

    if manifest is not None:
        manifest_result = verify_manifest(
            manifest
        )

        manifest_valid = manifest_result[
            "valid"
        ]

    return {
        "valid": (
            artifacts_valid
            and provenance_valid
            and finding_identity_valid
            and finding_provenance_valid
            and manifest_valid
        ),
        "artifact_count": len(
            artifact_results
        ),
        "verified_count": sum(
            1
            for result in artifact_results
            if result["valid"]
        ),
        "failed_count": sum(
            1
            for result in artifact_results
            if not result["valid"]
        ),
        "artifacts": artifact_results,
        "provenance": provenance_result,
        "finding_identity": (
            finding_identity_result
        ),
        "finding_provenance": (
            finding_provenance_result
        ),
        "manifest": manifest_result,
    }