import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.getenv("INCIDENT_DB_PATH", "/data/incidents.db")


class IncidentDatabase:
    def __init__(self, path=DB_PATH):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.lock = threading.RLock()
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    container_id TEXT NOT NULL,
                    container_name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    resolved_at TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id),
                    status TEXT NOT NULL,
                    summary TEXT,
                    root_cause TEXT,
                    confidence TEXT,
                    structured_json TEXT,
                    model_name TEXT,
                    investigated_at TEXT,
                    error_details TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_status_retry ON investigations(status, next_retry_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id, id DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS docker_events (
                    event_id TEXT PRIMARY KEY,
                    event_time TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    container_id TEXT,
                    container_name TEXT,
                    action TEXT NOT NULL,
                    attributes_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_docker_events_container_time ON docker_events(container_id, event_time)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_id TEXT NOT NULL,
                    container_name TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    cpu_percent REAL,
                    memory_usage_bytes INTEGER,
                    memory_limit_bytes INTEGER,
                    memory_percent REAL,
                    network_rx_bytes INTEGER,
                    network_tx_bytes INTEGER,
                    running INTEGER NOT NULL,
                    restart_count INTEGER NOT NULL,
                    health_status TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_metric_samples_container_time ON metric_samples(container_id, observed_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id),
                    container_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    action_result TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    context TEXT NOT NULL,
                    source TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    collected_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_operator_actions_incident_time ON operator_actions(incident_id, occurred_at)"
            )
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if schema_version < 2:
                connection.execute("PRAGMA user_version = 2")

    def _row(self, row):
        if row is None:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        return item

    def list(self, status=None):
        with self.lock, self.connect() as connection:
            if status:
                rows = connection.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM incidents ORDER BY created_at DESC"
                ).fetchall()
            return [self._row(row) for row in rows]

    def active(self):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status IN ('open', 'acknowledged') ORDER BY created_at DESC"
            ).fetchall()
            return [self._row(row) for row in rows]

    def get(self, incident_id):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._row(row)

    def find_active_by_fingerprint(self, fingerprint):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE fingerprint = ? AND status IN ('open', 'acknowledged') ORDER BY id DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            return self._row(row)

    def create(self, incident):
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents
                (fingerprint, container_id, container_name, type, severity, title, status, evidence,
                 created_at, updated_at, acknowledged_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["fingerprint"], incident["container_id"], incident["container_name"],
                    incident["type"], incident["severity"], incident["title"], incident["status"],
                    json.dumps(incident["evidence"]), incident["created_at"], incident["updated_at"],
                    incident.get("acknowledged_at"), incident.get("resolved_at"),
                ),
            )
            incident_id = cursor.lastrowid
        return self.get(incident_id)

    def update(self, incident_id, severity, title, evidence, timestamp):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET severity = ?, title = ?, evidence = ?, updated_at = ?
                WHERE id = ?
                """,
                (severity, title, json.dumps(evidence), timestamp, incident_id),
            )
        return self.get(incident_id)

    def update_status(self, incident_id, status, timestamp):
        fields = {"open": (None, None), "acknowledged": (timestamp, None), "resolved": (None, timestamp)}
        acknowledged_at, resolved_at = fields[status]
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?, acknowledged_at = COALESCE(?, acknowledged_at), resolved_at = COALESCE(?, resolved_at)
                WHERE id = ?
                """,
                (status, timestamp, acknowledged_at, resolved_at, incident_id),
            )
        return self.get(incident_id)

    def resolve_by_fingerprint(self, fingerprint, timestamp):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET status = 'resolved', resolved_at = ?, updated_at = ?
                WHERE fingerprint = ? AND status IN ('open', 'acknowledged')
                """,
                (timestamp, timestamp, fingerprint),
            )

    def store_docker_event(self, event):
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO docker_events
                (event_id, event_time, collected_at, container_id, container_name,
                 action, attributes_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"], event["event_time"], event["collected_at"],
                    event.get("container_id"), event.get("container_name"),
                    event["action"], json.dumps(event.get("attributes", {})),
                ),
            )
            self._cleanup_evidence(connection)
            return cursor.rowcount == 1

    def record_metric_sample(self, sample):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO metric_samples
                (container_id, container_name, observed_at, cpu_percent,
                 memory_usage_bytes, memory_limit_bytes, memory_percent,
                 network_rx_bytes, network_tx_bytes, running, restart_count,
                 health_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample["container_id"], sample["container_name"],
                    sample["observed_at"], sample.get("cpu_percent"),
                    sample.get("memory_usage_bytes"), sample.get("memory_limit_bytes"),
                    sample.get("memory_percent"), sample.get("network_rx_bytes"),
                    sample.get("network_tx_bytes"), int(sample["running"]),
                    sample.get("restart_count", 0), sample.get("health_status"),
                ),
            )
            self._cleanup_evidence(connection)

    def evidence_window(self, container_id, start_at, end_at):
        with self.lock, self.connect() as connection:
            event_rows = connection.execute(
                """
                SELECT * FROM docker_events
                WHERE event_time >= ? AND event_time <= ?
                  AND (container_id = ? OR container_id LIKE ?)
                ORDER BY event_time
                """,
                (start_at, end_at, container_id, f"{container_id}%"),
            ).fetchall()
            metric_rows = connection.execute(
                """
                SELECT * FROM metric_samples
                WHERE observed_at >= ? AND observed_at <= ?
                  AND (container_id = ? OR container_id LIKE ?)
                ORDER BY observed_at
                """,
                (start_at, end_at, container_id, f"{container_id}%"),
            ).fetchall()
        events = []
        for row in event_rows:
            item = dict(row)
            item["attributes"] = json.loads(item.pop("attributes_json"))
            events.append(item)
        return events, [dict(row) for row in metric_rows]

    def store_operator_action(self, action):
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO operator_actions
                (incident_id, container_id, action, action_result, actor, context,
                 source, occurred_at, collected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action["incident_id"], action["container_id"], action["action"],
                    action["action_result"], action["actor"], action["context"],
                    action["source"], action["occurred_at"], action["collected_at"],
                ),
            )
            row = connection.execute(
                "SELECT * FROM operator_actions WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
            return dict(row)

    def operator_actions_in_window(self, incident_id, start_at, end_at):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM operator_actions
                WHERE incident_id = ? AND occurred_at >= ? AND occurred_at <= ?
                ORDER BY occurred_at
                """,
                (incident_id, start_at, end_at),
            ).fetchall()
            return [dict(row) for row in rows]

    def _cleanup_evidence(self, connection):
        now = datetime.now(timezone.utc)
        event_days = max(1, int(os.getenv("DOCKER_EVENT_RETENTION_DAYS", "14")))
        metric_days = max(1, int(os.getenv("METRIC_RETENTION_DAYS", "7")))
        event_cutoff = (now.timestamp() - event_days * 86400)
        metric_cutoff = (now.timestamp() - metric_days * 86400)
        event_cutoff_text = datetime.fromtimestamp(
            event_cutoff, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        metric_cutoff_text = datetime.fromtimestamp(
            metric_cutoff, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        connection.execute("DELETE FROM docker_events WHERE event_time < ?", (event_cutoff_text,))
        connection.execute("DELETE FROM metric_samples WHERE observed_at < ?", (metric_cutoff_text,))
        connection.execute("DELETE FROM operator_actions WHERE occurred_at < ?", (event_cutoff_text,))
        connection.execute(
            "DELETE FROM docker_events WHERE event_id IN (SELECT event_id FROM docker_events ORDER BY event_time DESC LIMIT -1 OFFSET 20000)"
        )
        connection.execute(
            "DELETE FROM metric_samples WHERE id NOT IN (SELECT id FROM metric_samples ORDER BY id DESC LIMIT 100000)"
        )
        connection.execute(
            "DELETE FROM operator_actions WHERE id NOT IN (SELECT id FROM operator_actions ORDER BY id DESC LIMIT 20000)"
        )

    def _investigation_row(self, row):
        if row is None:
            return None
        item = dict(row)
        if item["structured_json"]:
            item["structured_json"] = json.loads(item["structured_json"])
        return item

    def create_investigation(self, incident_id, force=False):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            incident = connection.execute(
                "SELECT id FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if incident is None:
                return None, False

            latest = connection.execute(
                "SELECT * FROM investigations WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            if latest and not force:
                return self._investigation_row(latest), False

            cursor = connection.execute(
                """
                INSERT INTO investigations
                (incident_id, status, attempts, created_at, updated_at)
                VALUES (?, 'pending', 0, ?, ?)
                """,
                (incident_id, now, now),
            )
            row = connection.execute(
                "SELECT * FROM investigations WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
            return self._investigation_row(row), True

    def investigation_for_incident(self, incident_id):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM investigations WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            return self._investigation_row(row)

    def list_investigations(self, limit=50):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM investigations ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._investigation_row(row) for row in rows]

    def investigation_status_counts(self):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM investigations GROUP BY status"
            ).fetchall()
            return {row["status"]: row["count"] for row in rows}

    def investigation_queue_depth(self):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count FROM investigations
                WHERE status = 'pending'
                   OR (status = 'failed' AND attempts < ? AND next_retry_at IS NOT NULL)
                """,
                (max(1, int(os.getenv("INVESTIGATION_MAX_ATTEMPTS", "2"))),),
            ).fetchone()
            return row["count"]

    def reset_processing_investigations(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE investigations
                SET status = 'pending', error_details = 'Worker restarted during investigation',
                    next_retry_at = ?, updated_at = ?
                WHERE status = 'processing'
                """,
                (now, now),
            )

    def claim_investigation(self, max_attempts):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM investigations
                WHERE (status = 'pending' OR (status = 'failed' AND attempts < ?))
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY id ASC LIMIT 1
                """,
                (max_attempts, now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE investigations
                SET status = 'processing', attempts = attempts + 1, error_details = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, row["id"]),
            )
            claimed = connection.execute(
                "SELECT * FROM investigations WHERE id = ?", (row["id"],)
            ).fetchone()
            return self._investigation_row(claimed)

    def complete_investigation(self, investigation_id, result, model_name):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE investigations
                SET status = 'completed', summary = ?, root_cause = ?, confidence = ?,
                    structured_json = ?, model_name = ?, investigated_at = ?,
                    error_details = NULL, next_retry_at = NULL, updated_at = ?
                WHERE id = ?
                """,
                (
                    result["summary"], result["root_cause"], result["confidence"],
                    json.dumps(result), model_name, now, now, investigation_id,
                ),
            )

    def fail_investigation(self, investigation_id, error_details, retry_delay_seconds, max_attempts):
        now_dt = datetime.now(timezone.utc)
        now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT attempts FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            retry_at = None
            status = "failed"
            if row and row["attempts"] < max_attempts:
                retry_at = datetime.fromtimestamp(
                    now_dt.timestamp() + retry_delay_seconds, timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                status = "failed"
            connection.execute(
                """
                UPDATE investigations
                SET status = ?, error_details = ?, next_retry_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, error_details[:1000], retry_at, now, investigation_id),
            )
