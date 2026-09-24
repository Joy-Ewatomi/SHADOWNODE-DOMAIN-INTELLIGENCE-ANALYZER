from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    category: str
    name: str
    value: Any
    description: str | None = None
    evidence: list[dict] = field(default_factory=list)
    evidence_artifacts: list[str] = field(
        default_factory=list
    )
    confidence: str = "observed"
    finding_type: str = "observation"
    finding_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "name": self.name,
            "value": self.value,
            "description": self.description,
            "confidence": self.confidence,
            "finding_type": self.finding_type,
            "evidence": self.evidence,
            "evidence_artifacts": (
                self.evidence_artifacts
            ),
        }