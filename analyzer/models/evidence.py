from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    """
    Return the current UTC time as an ISO-8601 timestamp.
    """
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    value: Any
    source: str
    observed_at: str
    record_type: str | None = None
    classification: str = "observed"
    confidence: str = "high"

    @classmethod
    def create(
        cls,
        value: Any,
        source: str,
        record_type: str | None = None,
        classification: str = "observed",
        confidence: str = "high",
        observed_at: str | None = None,
    ):
        return cls(
            value=value,
            source=source,
            observed_at=observed_at or utc_now(),
            record_type=record_type,
            classification=classification,
            confidence=confidence,
        )

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "source": self.source,
            "observed_at": self.observed_at,
            "record_type": self.record_type,
            "classification": self.classification,
            "confidence": self.confidence,
        }
