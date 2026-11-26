"""Bounded, operator-approved Docker evidence collection.

This module intentionally exposes only a small action allowlist. It never
accepts shell commands or performs state-changing Docker operations.
"""
from datetime import datetime, timezone

from ai_investigator import redact_log_secrets


FOLLOWUP_ACTIONS = {
    "docker.container-events",
    "docker.container-logs",
}

MAX_WINDOW_SECONDS = 15 * 60
MAX_EVENT_ITEMS = 100
MAX_LOG_LINES = 300
MAX_LOG_BYTES = 20_000

EVENT_ALLOWLIST = {
    "start", "stop", "die", "kill", "oom", "restart",
    "health_status", "pause", "unpause",
}
ATTRIBUTE_ALLOWLIST = {"name", "image", "exitCode", "signal", "health"}


def _normalize_event(event):
    actor = event.get("Actor") or {}
    attributes = actor.get("Attributes") or {}
    return {
        "action": str(event.get("Action") or event.get("status") or "unknown")[:80],
        "timestamp": event.get("time"),
        "timestamp_nano": event.get("timeNano"),
        "container_id": str(actor.get("ID") or "")[:128],
        "attributes": {
            key: str(value)[:256]
            for key, value in attributes.items()
            if key in ATTRIBUTE_ALLOWLIST and value is not None
        },
    }


def collect_approved_read_only_followup(
    client, container, action_id, start_epoch, end_epoch
):
    """Collect a fixed, bounded time window for one pre-approved action."""
    if action_id not in FOLLOWUP_ACTIONS:
        raise ValueError("Unsupported read-only follow-up action")
    if not isinstance(start_epoch, int) or not isinstance(end_epoch, int):
        raise ValueError("Follow-up timestamps must be integer Unix seconds")
    if end_epoch < start_epoch:
        raise ValueError("Follow-up end time must not precede start time")
    if end_epoch - start_epoch > MAX_WINDOW_SECONDS:
        raise ValueError("Follow-up time window exceeds the 15-minute limit")

    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if action_id == "docker.container-events":
        events = []
        stream = client.events(
            decode=True,
            filters={
                "container": [container.id],
                "event": sorted(EVENT_ALLOWLIST),
            },
            since=start_epoch,
            until=end_epoch,
        )
        try:
            for event in stream:
                if len(events) >= MAX_EVENT_ITEMS:
                    break
                if not isinstance(event, dict):
                    continue
                events.append(_normalize_event(event))
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        return {
            "action_id": action_id,
            "collected_at": collected_at,
            "item_count": len(events),
            "events": events,
        }

    raw = container.logs(
        since=start_epoch,
        until=end_epoch,
        tail=MAX_LOG_LINES,
        timestamps=True,
        stdout=True,
        stderr=True,
    )
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        raw = ""
    truncated = len(raw.encode("utf-8", errors="replace")) > MAX_LOG_BYTES
    bounded = raw.encode("utf-8", errors="replace")[-MAX_LOG_BYTES:].decode(
        "utf-8", errors="replace"
    )
    redacted = redact_log_secrets(bounded)
    lines = [line[:500] for line in redacted.splitlines()[-MAX_LOG_LINES:]]
    return {
        "action_id": action_id,
        "collected_at": collected_at,
        "item_count": len(lines),
        "lines": lines,
        "possibly_truncated": truncated or len(lines) >= MAX_LOG_LINES,
    }
