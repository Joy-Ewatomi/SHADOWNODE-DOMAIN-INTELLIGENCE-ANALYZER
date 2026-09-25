from dataclasses import dataclass, field
from typing import Any

from .hashing import sha256_json


@dataclass
class EvidenceArtifact:
    """
    Represents a preserved evidence artifact.

    Artifacts can be either directly observed from an external
    source or derived from previously collected artifacts.
    """

    artifact_id: str
    artifact_type: str
    source: str
    collected_at: str
    data: Any
    sha256: str
    collector: str
    collector_version: str = "1.0"

    classification: str = "observed"

    parent_artifacts: list[str] = field(
        default_factory=list
    )

    context: dict[str, Any] = field(
        default_factory=dict
    )

    @classmethod
    def create(
        cls,
        artifact_id: str,
        artifact_type: str,
        source: str,
        collected_at: str,
        data: Any,
        collector: str,
        collector_version: str = "1.0",
        classification: str = "observed",
        parent_artifacts: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ):
        return cls(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            source=source,
            collected_at=collected_at,
            data=data,
            sha256=sha256_json(data),
            collector=collector,
            collector_version=collector_version,
            classification=classification,
            parent_artifacts=(
                parent_artifacts or []
            ),
            context=context or {},
        )

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "source": self.source,
            "collected_at": self.collected_at,
            "sha256": self.sha256,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "classification": self.classification,
            "parent_artifacts": self.parent_artifacts,
            "context": self.context,
            "data": self.data,
        }
