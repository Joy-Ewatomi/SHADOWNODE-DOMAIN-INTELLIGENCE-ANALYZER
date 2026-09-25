from dataclasses import dataclass, field

from .hashing import sha256_json
from .artifacts import EvidenceArtifact


@dataclass
class EvidenceManifest:
    """
    Collection-level manifest containing references to preserved
    evidence artifacts.

    The manifest begins in a mutable building state and can be
    finalized once collection is complete. Finalization records
    the completion timestamp and seals the manifest against
    further artifact additions.
    """

    case_id: str
    run_id: str
    created_at: str
    artifacts: list[dict] = field(default_factory=list)
    finalized_at: str | None = None
    sealed: bool = False
    _sha256: str | None = field(
        default=None,
        repr=False,
    )

    def add_artifact(
        self,
        artifact: EvidenceArtifact,
    ) -> None:
        if self.sealed:
            raise RuntimeError(
                "cannot add artifact to a finalized manifest"
            )

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

        self._sha256 = None

    def integrity_payload(self) -> dict:
        return {
            "case_id": self.case_id,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "finalized_at": self.finalized_at,
            "sealed": self.sealed,
            "artifact_count": len(
                self.artifacts
            ),
            "artifacts": self.artifacts,
        }

    def calculate_hash(self) -> str:
        return sha256_json(
            self.integrity_payload()
        )

    def finalize(
        self,
        finalized_at: str,
    ) -> None:
        """
        Finalize and seal the manifest.

        A finalized manifest cannot accept additional artifacts.
        Its final hash represents the complete collection state.
        """

        if self.sealed:
            raise RuntimeError(
                "manifest is already finalized"
            )

        self.finalized_at = finalized_at
        self.sealed = True
        self._sha256 = self.calculate_hash()

    def to_dict(self) -> dict:
        payload = self.integrity_payload()

        if self.sealed:
            payload["sha256"] = self._sha256
        else:
            payload["sha256"] = self.calculate_hash()

        return payload
