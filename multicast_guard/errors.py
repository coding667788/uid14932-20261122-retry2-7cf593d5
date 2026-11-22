"""Structured validation errors with JSON-pointer-like field paths."""

from __future__ import annotations

from typing import Any


class ValidationError(Exception):
    """Raised when a case document fails schema or semantic validation."""

    def __init__(self, errors: list[dict[str, str]]):
        self.errors = errors
        super().__init__("; ".join(f"{e['path']}: {e['message']}" for e in errors))

    def to_payload(self) -> dict[str, Any]:
        return {"status": "error", "error_type": "validation", "errors": self.errors}


class InputError(Exception):
    """Raised for unreadable / non-JSON input files."""

    def __init__(self, path: str, message: str):
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": "error",
            "error_type": "input",
            "errors": [{"path": self.path, "message": self.message}],
        }


class Validator:
    """Collects every validation error instead of failing on the first one."""

    def __init__(self) -> None:
        self.errors: list[dict[str, str]] = []

    def fail(self, path: str, message: str) -> None:
        self.errors.append({"path": path, "message": message})

    def require(self, cond: bool, path: str, message: str) -> bool:
        if not cond:
            self.fail(path, message)
        return cond

    def finish(self) -> None:
        if self.errors:
            raise ValidationError(self.errors)
