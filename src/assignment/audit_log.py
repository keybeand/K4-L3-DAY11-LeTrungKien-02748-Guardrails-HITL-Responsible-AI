"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        req_key = request_id or f"{user_id}_{len(self.logs)}"
        self._open[req_key] = datetime.now(timezone.utc).timestamp()
        self.logs.append({
            "request_id": req_key,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "input": text,
            "status": "pending",
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        now = datetime.now(timezone.utc).timestamp()
        req_key = request_id or f"{user_id}_{len(self.logs) - 1}"
        start_time = self._open.pop(req_key, now)
        latency = round(now - start_time, 4)

        # Cập nhật bản ghi tương ứng trong self.logs nếu có
        for entry in reversed(self.logs):
            if entry.get("request_id") == req_key:
                entry.update({
                    "response": text,
                    "blocked": blocked,
                    "layer": layer,
                    "latency_sec": latency,
                    "status": "completed",
                })
                return

        # Nếu chưa có bản ghi input trước đó
        self.logs.append({
            "request_id": req_key,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "response": text,
            "blocked": blocked,
            "layer": layer,
            "latency_sec": latency,
            "status": "completed",
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root outputs/ by default."""
        target_path = Path(filepath or default_audit_log_path())
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
