from analyzer.evidence.artifacts import EvidenceArtifact
from analyzer.evidence.collector import EvidenceCollector
from analyzer.evidence.hashing import sha256_json
from analyzer.evidence.verify import (
    verify_artifact,
    verify_manifest,
    verify_provenance,
    verify_finding_identity,
    verify_finding_provenance,
)


def test_sha256_json_is_deterministic():
    data_a = {
        "b": 2,
        "a": 1,
    }

    data_b = {
        "a": 1,
        "b": 2,
    }

    assert sha256_json(data_a) == sha256_json(data_b)


def test_sha256_json_changes_when_data_changes():
    original = {
        "value": "original",
    }

    modified = {
        "value": "modified",
    }

    assert sha256_json(original) != sha256_json(modified)


def test_evidence_artifact_hash_is_valid():
    artifact = EvidenceArtifact.create(
        artifact_id="case-0001",
        artifact_type="test",
        source="unit-test",
        collected_at="2026-09-24T00:00:00+00:00",
        data={
            "value": "hello",
        },
        collector="Test Collector",
        collector_version="1.0",
    )

    result = verify_artifact(
        artifact.to_dict()
    )

    assert result["valid"] is True
    assert result["expected_sha256"] == (
        result["actual_sha256"]
    )


def test_evidence_collector_creates_sequential_artifacts():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    first = collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": 1},
        collector="Test Collector",
    )

    second = collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": 2},
        collector="Test Collector",
    )

    assert first["artifact_id"] == "test-run-0001"
    assert second["artifact_id"] == "test-run-0002"
    assert len(collector.artifacts) == 2


def test_artifact_verification_passes():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    artifact = collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "valid"},
        collector="Test Collector",
    )

    result = verify_artifact(artifact)

    assert result["valid"] is True


def test_artifact_verification_detects_tampering():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    artifact = collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "original"},
        collector="Test Collector",
    )

    artifact["data"]["value"] = "tampered"

    result = verify_artifact(artifact)

    assert result["valid"] is False
    assert (
        result["expected_sha256"]
        != result["actual_sha256"]
    )


def test_artifact_provenance_passes_for_valid_parent():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    parent = collector.add(
        artifact_type="raw",
        source="unit-test",
        data={"value": "parent"},
        collector="Test Collector",
    )

    child = collector.add(
        artifact_type="derived",
        source="unit-test",
        data={"value": "child"},
        collector="Test Collector",
        classification="derived",
        parent_artifacts=[
            parent["artifact_id"],
        ],
    )

    result = verify_provenance(
        collector.artifacts
    )

    assert result["valid"] is True
    assert child["parent_artifacts"] == [
        parent["artifact_id"]
    ]


def test_artifact_provenance_detects_missing_parent():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.add(
        artifact_type="derived",
        source="unit-test",
        data={"value": "child"},
        collector="Test Collector",
        classification="derived",
        parent_artifacts=[
            "missing-artifact",
        ],
    )

    result = verify_provenance(
        collector.artifacts
    )

    assert result["valid"] is False
    assert result["error_count"] > 0


def test_finding_identity_passes_for_unique_ids():
    findings = [
        {
            "finding_id": "case-finding-0001",
            "name": "First",
        },
        {
            "finding_id": "case-finding-0002",
            "name": "Second",
        },
    ]

    result = verify_finding_identity(findings)

    assert result["valid"] is True
    assert result["duplicate_finding_ids"] == []


def test_finding_identity_detects_duplicate_ids():
    findings = [
        {
            "finding_id": "case-finding-0001",
            "name": "First",
        },
        {
            "finding_id": "case-finding-0001",
            "name": "Duplicate",
        },
    ]

    result = verify_finding_identity(findings)

    assert result["valid"] is False
    assert (
        "case-finding-0001"
        in result["duplicate_finding_ids"]
    )


def test_finding_identity_detects_missing_id():
    findings = [
        {
            "name": "Missing ID",
        },
    ]

    result = verify_finding_identity(findings)

    assert result["valid"] is False
    assert result["error_count"] > 0


def test_finding_provenance_passes_for_valid_artifact_reference():
    findings = [
        {
            "finding_id": "case-finding-0001",
            "name": "Test finding",
            "evidence_artifacts": [
                "case-0001",
            ],
        }
    ]

    artifacts = [
        {
            "artifact_id": "case-0001",
        }
    ]

    result = verify_finding_provenance(
        findings,
        artifacts,
    )

    assert result["valid"] is True


def test_finding_provenance_detects_missing_artifact_reference():
    findings = [
        {
            "finding_id": "case-finding-0001",
            "name": "Test finding",
            "evidence_artifacts": [
                "missing-artifact",
            ],
        }
    ]

    artifacts = [
        {
            "artifact_id": "case-0001",
        }
    ]

    result = verify_finding_provenance(
        findings,
        artifacts,
    )

    assert result["valid"] is False
    assert result["error_count"] > 0


def test_manifest_verification_passes():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "hello"},
        collector="Test Collector",
    )

    result = verify_manifest(
        collector.manifest.to_dict()
    )

    assert result["valid"] is True
    assert (
        result["expected_sha256"]
        == result["actual_sha256"]
    )


def test_manifest_verification_detects_tampering():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "hello"},
        collector="Test Collector",
    )

    manifest_data = collector.manifest.to_dict()

    manifest_data["sha256"] = "tampered"

    result = verify_manifest(
        manifest_data
    )

    assert result["valid"] is False
    assert (
        result["expected_sha256"]
        != result["actual_sha256"]
    )

def test_manifest_can_be_finalized_and_sealed():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "final"},
        collector="Test Collector",
    )

    finalized = collector.finalize()

    assert finalized["case_id"] == "test-case"
    assert finalized["run_id"] == "test-run"
    assert finalized["sealed"] is True
    assert finalized["finalized_at"]
    assert finalized["artifact_count"] == 1
    assert finalized["sha256"]

    assert collector.manifest.to_dict() == finalized


def test_finalized_manifest_rejects_new_artifacts():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.add(
        artifact_type="test",
        source="unit-test",
        data={"value": "before"},
        collector="Test Collector",
    )

    collector.finalize()

    try:
        collector.add(
            artifact_type="test",
            source="unit-test",
            data={"value": "after"},
            collector="Test Collector",
        )
    except RuntimeError as exc:
        assert str(exc) == (
            "cannot add artifact to a finalized manifest"
        )
    else:
        raise AssertionError(
            "Expected RuntimeError after manifest finalization"
        )


def test_manifest_cannot_be_finalized_twice():
    collector = EvidenceCollector(
        case_id="test-case",
        run_id="test-run",
        collector_version="1.0",
    )

    collector.finalize()

    try:
        collector.finalize()
    except RuntimeError as exc:
        assert str(exc) == (
            "manifest is already finalized"
        )
    else:
        raise AssertionError(
            "Expected RuntimeError when finalizing twice"
        )
