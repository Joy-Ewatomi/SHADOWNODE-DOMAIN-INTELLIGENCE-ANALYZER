from datetime import datetime, timezone
from typing import Any

from .artifacts import EvidenceArtifact
from .manifest import EvidenceManifest


COLLECTOR_VERSION = "1.0"


def utc_now() -> str:
    """
    Return the current UTC time as an ISO-8601 timestamp.
    """

    return datetime.now(timezone.utc).isoformat()


class EvidenceCollector:
    """
    Collects and preserves raw and derived evidence artifacts.
    """

    def __init__(
        self,
        case_id: str,
        collector_version: str = COLLECTOR_VERSION,
    ):
        self.case_id = case_id
        self.collector_version = collector_version

        self.created_at = utc_now()

        self.manifest = EvidenceManifest(
            case_id=case_id,
            created_at=self.created_at,
        )

        self.artifacts: list[dict] = []

        self._sequence = 0

    def add(
        self,
        artifact_type: str,
        source: str,
        data: Any,
        collector: str,
        classification: str = "observed",
        parent_artifacts: list[str] | None = None,
    ) -> dict:
        """
        Preserve a collection result as an evidence artifact.

        classification:
            observed
            derived

        parent_artifacts:
            Artifact IDs used to produce this artifact.
        """

        if classification not in {
            "observed",
            "derived",
        }:
            raise ValueError(
                "classification must be "
                "'observed' or 'derived'"
            )

        self._sequence += 1

        artifact_id = (
            f"{self.case_id}-"
            f"{self._sequence:04d}"
        )

        collected_at = utc_now()

        artifact = EvidenceArtifact.create(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            source=source,
            collected_at=collected_at,
            data=data,
            collector=collector,
            collector_version=self.collector_version,
            classification=classification,
            parent_artifacts=(
                parent_artifacts or []
            ),
        )

        artifact_dict = artifact.to_dict()

        self.artifacts.append(
            artifact_dict
        )

        self.manifest.add_artifact(
            artifact
        )

        return artifact_dict

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "artifact_count": len(self.artifacts),
            "artifacts": self.artifacts,
            "manifest": self.manifest.to_dict(),
        }
