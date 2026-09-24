from dataclasses import dataclass, field

from .hashing import sha256_json
from .artifacts import EvidenceArtifact


@dataclass
class EvidenceManifest:
    """
    Collection-level manifest containing references to preserved
    evidence artifacts.
    """

    case_id: str
    created_at: str
    artifacts: list[dict] = field(default_factory=list)

    def add_artifact(
        self,
        artifact: EvidenceArtifact,
    ) -> None:
        self.artifacts.append({
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type,
            "source": artifact.source,
            "collected_at": artifact.collected_at,
            "sha256": artifact.sha256,
            "collector": artifact.collector,
            "collector_version": (
                artifact.collector_version
            ),
            "classification": artifact.classification,
            "parent_artifacts": (
                artifact.parent_artifacts
            ),
        })

    def integrity_payload(self) -> dict:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "artifact_count": len(
                self.artifacts
            ),
            "artifacts": self.artifacts,
        }

    def calculate_hash(self) -> str:
        return sha256_json(
            self.integrity_payload()
        )

    def to_dict(self) -> dict:
        payload = self.integrity_payload()

        payload["sha256"] = (
            self.calculate_hash()
        )

        return payload
