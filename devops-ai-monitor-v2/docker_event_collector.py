import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timezone

import docker
import requests

from ai_investigator import redact_log_secrets


logger = logging.getLogger(__name__)
EVENT_ACTIONS = (
    "create",
    "start",
    "stop",
    "die",
    "kill",
    "oom",
    "restart",
    "destroy",
    "health_status",
)
SAFE_EVENT_ATTRIBUTES = {
    "name",
    "image",
    "exitCode",
    "signal",
    "health_status",
    "restartCount",
}


def _utc_timestamp(timestamp, nanoseconds=None):
    if nanoseconds:
        value = datetime.fromtimestamp(nanoseconds / 1_000_000_000, timezone.utc)
    else:
        value = datetime.fromtimestamp(timestamp, timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class DockerEventCollector:
    def __init__(self, database):
        self.database = database
        self.stop_event = threading.Event()
        self.status_lock = threading.Lock()
        self.client_lock = threading.Lock()
        self.thread = None
        self.client = None
        self.status = {
            "running": False,
            "connected": False,
            "last_event_at": None,
            "last_error": None,
            "events_collected": 0,
            "reconnects": 0,
        }

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run, name="docker-event-collector", daemon=True
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        with self.client_lock:
            if self.client is not None:
                self.client.close()
                self.client = None
        if self.thread:
            self.thread.join(timeout=5)

    def get_status(self):
        with self.status_lock:
            return dict(self.status)

    def _run(self):
        with self.status_lock:
            self.status["running"] = True
        reconnect_delay = 1
        since = None
        try:
            while not self.stop_event.is_set():
                client = None
                try:
                    client = docker.from_env()
                    with self.client_lock:
                        self.client = client
                    client.ping()
                    with self.status_lock:
                        self.status["connected"] = True
                        self.status["last_error"] = None
                    filters = {
                        "type": ["container"],
                        "event": list(EVENT_ACTIONS),
                    }
                    for event in client.events(
                        decode=True, since=since, filters=filters
                    ):
                        if self.stop_event.is_set():
                            break
                        if self._store_event(event):
                            event_time = event.get("timeNano") or event.get("time")
                            if event_time:
                                since = max(int(since or 0), int(event["time"]))
                        if self.stop_event.is_set():
                            break
                    reconnect_delay = 1
                except (
                    docker.errors.DockerException,
                    OSError,
                    ValueError,
                    requests.exceptions.RequestException,
                ) as exc:
                    if not self.stop_event.is_set():
                        with self.status_lock:
                            self.status["connected"] = False
                            self.status["last_error"] = type(exc).__name__
                            self.status["reconnects"] += 1
                        logger.warning(
                            "Docker event stream interrupted (%s); reconnecting",
                            type(exc).__name__,
                        )
                finally:
                    with self.client_lock:
                        if self.client is client:
                            self.client = None
                    if client is not None:
                        try:
                            client.close()
                        except docker.errors.DockerException:
                            logger.debug("Docker event client was already disconnected")
                if not self.stop_event.is_set():
                    self.stop_event.wait(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 30)
        finally:
            with self.status_lock:
                self.status["running"] = False
                self.status["connected"] = False

    def _store_event(self, event):
        if not isinstance(event, dict):
            return False
        actor = event.get("Actor") or {}
        actor_id = actor.get("ID")
        attributes = actor.get("Attributes") or {}
        event_type = event.get("Type") or "container"
        action = event.get("Action") or event.get("status") or "unknown"
        timestamp = int(event.get("time") or 0)
        if not timestamp:
            return False
        nanoseconds = int(event.get("timeNano") or 0)
        identity = "|".join(
            (
                str(event_type),
                str(action),
                str(actor_id or ""),
                str(nanoseconds or timestamp),
            )
        )
        record = {
            "event_id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "event_time": _utc_timestamp(timestamp, nanoseconds),
            "collected_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "container_id": actor_id,
            "container_name": attributes.get("name"),
            "action": str(action)[:80],
            "attributes": {
                key: redact_log_secrets(str(value)[:256])
                for key, value in attributes.items()
                if key in SAFE_EVENT_ATTRIBUTES
            },
        }
        try:
            stored = self.database.store_docker_event(record)
        except sqlite3.Error as exc:
            with self.status_lock:
                self.status["last_error"] = f"SQLite {type(exc).__name__}"
            logger.error(
                "Could not persist Docker event for container %s (%s)",
                (actor_id or "")[:12],
                type(exc).__name__,
            )
            return False
        with self.status_lock:
            self.status["last_event_at"] = record["event_time"]
            if stored:
                self.status["events_collected"] += 1
        return stored
