import base64
import json
from typing import Any


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str | None, expected_keys: set[str]) -> dict[str, Any] | None:
    if value is None:
        return None
    if len(value) > 2048:
        raise ValueError("Cursor is too long")
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Cursor is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("Cursor is invalid")
    return payload
