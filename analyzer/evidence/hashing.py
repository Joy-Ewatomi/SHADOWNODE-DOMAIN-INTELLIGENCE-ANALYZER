import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """
    Serialize a Python value into deterministic UTF-8 JSON bytes.

    These exact bytes are what get hashed and preserved.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """
    Calculate SHA-256 for raw bytes.
    """

    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    """
    Calculate SHA-256 over canonical JSON representation.
    """

    return sha256_bytes(
        canonical_json_bytes(value)
    )
