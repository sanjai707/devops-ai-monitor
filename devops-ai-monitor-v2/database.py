import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.getenv("INCIDENT_DB_PATH", "/data/incidents.db")


class IncidentConnection(sqlite3.Connection):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
        return False


class IncidentDatabase:
    def __init__(self, path=DB_PATH):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.lock = threading.RLock()
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            check_same_thread=False,
            factory=IncidentConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
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
            try:
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_active_incidents_fingerprint
                    ON incidents(fingerprint)
                    WHERE status IN ('open', 'acknowledged', 'investigating', 'reopened')
                    """
                )
            except sqlite3.OperationalError:
                # Existing databases may contain duplicate active records. Preserve
                # those records and allow the application transaction guard to
                # prevent new duplicates until an operator performs reconciliation.
                pass
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
                CREATE TABLE IF NOT EXISTS investigation_followups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id),
                    source_investigation_id INTEGER NOT NULL REFERENCES investigations(id),
                    reassessment_investigation_id INTEGER REFERENCES investigations(id),
                    container_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    approved_at TEXT NOT NULL,
                    collected_at TEXT,
                    time_window_json TEXT NOT NULL,
                    result_json TEXT,
                    limitations_json TEXT NOT NULL DEFAULT '[]',
                    error_details TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_investigation_id, action_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_followups_incident ON investigation_followups(incident_id, id)"
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
            metric_columns = {
                row[1]: row
                for row in connection.execute("PRAGMA table_info(metric_samples)").fetchall()
            }
            if "network_rx_rate_bytes_per_sec" not in metric_columns:
                connection.execute(
                    "ALTER TABLE metric_samples ADD COLUMN network_rx_rate_bytes_per_sec REAL"
                )
            if "network_tx_rate_bytes_per_sec" not in metric_columns:
                connection.execute(
                    "ALTER TABLE metric_samples ADD COLUMN network_tx_rate_bytes_per_sec REAL"
                )
            if "counter_reset" not in metric_columns:
                connection.execute(
                    "ALTER TABLE metric_samples ADD COLUMN counter_reset INTEGER NOT NULL DEFAULT 0"
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
            incident_columns = {
                row[1]: row
                for row in connection.execute("PRAGMA table_info(incidents)").fetchall()
            }
            if "first_seen_at" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN first_seen_at TEXT"
                )
                connection.execute(
                    "UPDATE incidents SET first_seen_at = created_at WHERE first_seen_at IS NULL"
                )
            if "last_seen_at" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN last_seen_at TEXT"
                )
                connection.execute(
                    "UPDATE incidents SET last_seen_at = updated_at WHERE last_seen_at IS NULL"
                )
            if "event_count" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN event_count INTEGER NOT NULL DEFAULT 1"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL REFERENCES incidents(id),
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incident_audit_incident_time ON incident_audit(incident_id, occurred_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    incident_id INTEGER,
                    verification_status TEXT NOT NULL,
                    approval_status TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    tags TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_knowledge_status ON knowledge_records(approval_status, verification_status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_records(category)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    knowledge_id INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    approval_status TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    change_reason TEXT NOT NULL,
                    changed_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER,
                    investigation_id INTEGER,
                    original_query TEXT NOT NULL,
                    model_response_json TEXT NOT NULL,
                    model_version TEXT,
                    prompt_version TEXT,
                    retrieved_knowledge_ids TEXT NOT NULL,
                    feedback_type TEXT NOT NULL,
                    user_correction TEXT,
                    occurred_at TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    proposed_knowledge_id INTEGER
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_incident ON investigation_feedback(incident_id, occurred_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_status ON investigation_feedback(review_status)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_name TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL
                )
                """
            )
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if schema_version < 7:
                connection.execute("PRAGMA user_version = 7")

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
                "SELECT * FROM incidents WHERE status IN ('open', 'acknowledged', 'investigating', 'reopened') ORDER BY created_at DESC"
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
                "SELECT * FROM incidents WHERE fingerprint = ? AND status IN ('open', 'acknowledged', 'investigating', 'reopened') ORDER BY id DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            return self._row(row)

    def create(self, incident):
        with self.lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM incidents
                WHERE fingerprint = ? AND status IN
                    ('open', 'acknowledged', 'investigating', 'reopened')
                ORDER BY id DESC LIMIT 1
                """,
                (incident["fingerprint"],),
            ).fetchone()
            if existing:
                return self._row(existing)
            cursor = connection.execute(
                """
                INSERT INTO incidents
                (fingerprint, container_id, container_name, type, severity, title, status, evidence,
                 created_at, updated_at, acknowledged_at, resolved_at, first_seen_at,
                 last_seen_at, event_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["fingerprint"], incident["container_id"], incident["container_name"],
                    incident["type"], incident["severity"], incident["title"], incident["status"],
                    json.dumps(incident["evidence"]), incident["created_at"], incident["updated_at"],
                    incident.get("acknowledged_at"), incident.get("resolved_at"),
                    incident["created_at"], incident["updated_at"], 1,
                ),
            )
            incident_id = cursor.lastrowid
            self._record_incident_audit(
                connection, incident_id, None, incident["status"],
                "created", "Incident created", "monitor"
            )
        return self.get(incident_id)

    def update(self, incident_id, severity, title, evidence, timestamp):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET severity = ?, title = ?, evidence = ?, updated_at = ?,
                    last_seen_at = ?, event_count = event_count + 1
                WHERE id = ?
                """,
                (severity, title, json.dumps(evidence), timestamp, timestamp, incident_id),
            )
        return self.get(incident_id)

    def update_status(self, incident_id, status, timestamp):
        fields = {
            "open": (None, None),
            "acknowledged": (timestamp, None),
            "investigating": (None, None),
            "resolved": (None, timestamp),
            "reopened": (None, None),
            "suppressed": (None, None),
        }
        if status not in fields:
            raise ValueError("Unsupported incident status")
        acknowledged_at, resolved_at = fields[status]
        with self.lock, self.connect() as connection:
            prior = connection.execute(
                "SELECT status FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if prior is None:
                return None
            allowed = {
                "open": {"acknowledged", "investigating", "resolved", "suppressed", "reopened"},
                "acknowledged": {"investigating", "resolved", "suppressed", "reopened"},
                "investigating": {"acknowledged", "resolved", "suppressed", "reopened"},
                "resolved": {"reopened"},
                "reopened": {"acknowledged", "investigating", "resolved", "suppressed"},
                "suppressed": {"reopened", "resolved"},
            }
            previous_status = prior["status"]
            if previous_status != status and status not in allowed.get(previous_status, set()):
                raise ValueError(
                    f"Unsupported incident status transition: {previous_status} -> {status}"
                )
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?, acknowledged_at = COALESCE(?, acknowledged_at), resolved_at = COALESCE(?, resolved_at)
                WHERE id = ?
                """,
                (status, timestamp, acknowledged_at, resolved_at, incident_id),
            )
            self._record_incident_audit(
                connection,
                incident_id,
                prior["status"] if prior else None,
                status,
                "status_changed",
                f"Status changed to {status}",
                "operator",
            )
        return self.get(incident_id)

    def add_incident_comment(self, incident_id, comment, actor="operator"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            prior = connection.execute(
                "SELECT status FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if prior is None:
                return None
            self._record_incident_audit(
                connection,
                incident_id,
                prior["status"],
                prior["status"],
                "comment",
                comment,
                actor,
                now,
            )
        return self.get(incident_id)

    def list_incident_audit(self, incident_id):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM incident_audit
                WHERE incident_id = ? ORDER BY occurred_at ASC, id ASC
                """,
                (incident_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _record_incident_audit(
        self,
        connection,
        incident_id,
        from_status,
        to_status,
        action,
        details,
        actor,
        occurred_at=None,
    ):
        occurred_at = occurred_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        connection.execute(
            """
            INSERT INTO incident_audit
            (incident_id, from_status, to_status, action, details, actor, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id, from_status, to_status, action,
                details[:2000], actor[:80], occurred_at,
            ),
        )

    def resolve_by_fingerprint(self, fingerprint, timestamp):
        """Resolve every active incident for a recovered condition and audit it."""
        active_statuses = ("open", "acknowledged", "investigating", "reopened")
        with self.lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT id, status FROM incidents
                WHERE fingerprint = ? AND status IN
                    ('open', 'acknowledged', 'investigating', 'reopened')
                """,
                (fingerprint,),
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    UPDATE incidents
                    SET status = 'resolved', resolved_at = ?, updated_at = ?
                    WHERE id = ? AND status = ?
                    """,
                    (timestamp, timestamp, row["id"], row["status"]),
                )
                self._record_incident_audit(
                    connection,
                    row["id"],
                    row["status"],
                    "resolved",
                    "automatically_resolved",
                    "Monitoring condition recovered; incident automatically resolved",
                    "monitor",
                    timestamp,
                )
            return len(rows)

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
            previous = connection.execute(
                """
                SELECT observed_at, network_rx_bytes, network_tx_bytes
                FROM metric_samples
                WHERE container_id = ? OR container_id LIKE ?
                ORDER BY observed_at DESC LIMIT 1
                """,
                (sample["container_id"], f"{sample['container_id']}%"),
            ).fetchone()
            rx_rate = None
            tx_rate = None
            counter_reset = 0
            if previous:
                try:
                    previous_time = datetime.fromisoformat(
                        previous["observed_at"].replace("Z", "+00:00")
                    )
                    current_time = datetime.fromisoformat(
                        sample["observed_at"].replace("Z", "+00:00")
                    )
                    elapsed = (current_time - previous_time).total_seconds()
                    rx = sample.get("network_rx_bytes")
                    tx = sample.get("network_tx_bytes")
                    if elapsed > 0 and rx is not None and previous["network_rx_bytes"] is not None:
                        if rx >= previous["network_rx_bytes"]:
                            rx_rate = round((rx - previous["network_rx_bytes"]) / elapsed, 3)
                        else:
                            counter_reset = 1
                    if elapsed > 0 and tx is not None and previous["network_tx_bytes"] is not None:
                        if tx >= previous["network_tx_bytes"]:
                            tx_rate = round((tx - previous["network_tx_bytes"]) / elapsed, 3)
                        else:
                            counter_reset = 1
                except (TypeError, ValueError):
                    rx_rate = None
                    tx_rate = None
            connection.execute(
                """
                INSERT INTO metric_samples
                (container_id, container_name, observed_at, cpu_percent,
                 memory_usage_bytes, memory_limit_bytes, memory_percent,
                 network_rx_bytes, network_tx_bytes, running, restart_count,
                 health_status, network_rx_rate_bytes_per_sec,
                 network_tx_rate_bytes_per_sec, counter_reset)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample["container_id"], sample["container_name"],
                    sample["observed_at"], sample.get("cpu_percent"),
                    sample.get("memory_usage_bytes"), sample.get("memory_limit_bytes"),
                    sample.get("memory_percent"), sample.get("network_rx_bytes"),
                    sample.get("network_tx_bytes"), int(sample["running"]),
                    sample.get("restart_count", 0), sample.get("health_status"),
                    rx_rate, tx_rate, counter_reset,
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

    def metric_history(self, container_id, start_at, end_at, limit=720):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM metric_samples
                WHERE observed_at >= ? AND observed_at <= ?
                  AND (container_id = ? OR container_id LIKE ?)
                ORDER BY observed_at DESC LIMIT ?
                """,
                (start_at, end_at, container_id, f"{container_id}%", limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def metric_summary(self, container_id, start_at, end_at):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS sample_count,
                    MIN(observed_at) AS first_sample_at,
                    MAX(observed_at) AS last_sample_at,
                    AVG(cpu_percent) AS avg_cpu_percent,
                    MAX(cpu_percent) AS max_cpu_percent,
                    AVG(memory_percent) AS avg_memory_percent,
                    MAX(memory_percent) AS max_memory_percent,
                    MAX(restart_count) AS max_restart_count,
                    SUM(CASE WHEN counter_reset = 1 THEN 1 ELSE 0 END) AS counter_resets
                FROM metric_samples
                WHERE observed_at >= ? AND observed_at <= ?
                  AND (container_id = ? OR container_id LIKE ?)
                """,
                (start_at, end_at, container_id, f"{container_id}%"),
            ).fetchone()
        return dict(row) if row else {}

    def incident_timeline(self, incident_id):
        with self.lock, self.connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if incident is None:
                return None
            incident_item = dict(incident)
            incident_item["evidence"] = json.loads(incident_item["evidence"])
            investigations = connection.execute(
                """
                SELECT id, incident_id, status, summary, root_cause, confidence,
                       model_name, investigated_at, error_details, attempts,
                       created_at, updated_at
                FROM investigations
                WHERE incident_id = ? ORDER BY created_at ASC
                """,
                (incident_id,),
            ).fetchall()
            action_rows = connection.execute(
                """
                SELECT * FROM operator_actions
                WHERE incident_id = ? ORDER BY occurred_at ASC
                """,
                (incident_id,),
            ).fetchall()
        return {
            "incident": incident_item,
            "investigations": [dict(row) for row in investigations],
            "operator_actions": [dict(row) for row in action_rows],
        }

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

    def _investigation_followup_row(self, row):
        if row is None:
            return None
        item = dict(row)
        item["time_window"] = json.loads(item.pop("time_window_json") or "{}")
        item["result"] = json.loads(item.pop("result_json") or "null")
        item["limitations"] = json.loads(item.pop("limitations_json") or "[]")
        return item

    def create_investigation_followup(self, record):
        """Persist an explicit operator approval before read-only collection starts."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO investigation_followups
                (incident_id, source_investigation_id, container_id, action_id,
                 status, approved_by, approved_at, time_window_json,
                 limitations_json, created_at)
                VALUES (?, ?, ?, ?, 'collecting', ?, ?, ?, '[]', ?)
                """,
                (
                    record["incident_id"], record["source_investigation_id"],
                    record["container_id"], record["action_id"],
                    record["approved_by"], record["approved_at"],
                    json.dumps(record["time_window"]), now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM investigation_followups WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return self._investigation_followup_row(row)

    def complete_investigation_followup(
        self, followup_id, result, status="collected", limitations=None,
        error_details=None, collected_at=None,
    ):
        if status not in {"collected", "unavailable", "failed"}:
            raise ValueError("Invalid investigation follow-up status")
        collected_at = collected_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE investigation_followups
                SET status = ?, result_json = ?, limitations_json = ?,
                    error_details = ?, collected_at = ?
                WHERE id = ?
                """,
                (
                    status, json.dumps(result), json.dumps(limitations or []),
                    (error_details or "")[:500] or None, collected_at, followup_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM investigation_followups WHERE id = ?",
                (followup_id,),
            ).fetchone()
            return self._investigation_followup_row(row)

    def link_followup_reassessment(self, followup_id, investigation_id):
        with self.lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE investigation_followups
                SET reassessment_investigation_id = ?
                WHERE id = ?
                """,
                (investigation_id, followup_id),
            )
            row = connection.execute(
                "SELECT * FROM investigation_followups WHERE id = ?",
                (followup_id,),
            ).fetchone()
            return self._investigation_followup_row(row)

    def investigation_followups_for_incident(self, incident_id):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM investigation_followups
                WHERE incident_id = ?
                ORDER BY id ASC
                """,
                (incident_id,),
            ).fetchall()
            return [self._investigation_followup_row(row) for row in rows]

    def create_knowledge(self, record):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO knowledge_records
                (title, content, category, source, incident_id, verification_status,
                 approval_status, confidence, version, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    record["title"], record["content"], record["category"],
                    record["source"], record.get("incident_id"),
                    record.get("verification_status", "unverified"),
                    record.get("approval_status", "pending_review"),
                    record.get("confidence", "low"),
                    json.dumps(record.get("tags", [])), now, now,
                ),
            )
            knowledge_id = cursor.lastrowid
            self._record_knowledge_version(
                connection, knowledge_id, 1, record,
                record.get("changed_by", "system"),
                record.get("change_reason", "created"),
                now,
            )
            row = connection.execute(
                "SELECT * FROM knowledge_records WHERE id = ?", (knowledge_id,)
            ).fetchone()
        return self._knowledge_row(row)

    def update_knowledge(self, knowledge_id, record, changed_by="operator",
                         change_reason="updated"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM knowledge_records WHERE id = ?", (knowledge_id,)
            ).fetchone()
            if row is None:
                return None
            current = dict(row)
            next_version = current["version"] + 1
            content = record.get("content", current["content"])
            title = record.get("title", current["title"])
            category = record.get("category", current["category"])
            source = record.get("source", current["source"])
            verification = record.get(
                "verification_status", current["verification_status"]
            )
            approval = record.get("approval_status", current["approval_status"])
            confidence = record.get("confidence", current["confidence"])
            tags = record.get("tags")
            tags_json = json.dumps(tags) if tags is not None else current["tags"]
            connection.execute(
                """
                UPDATE knowledge_records
                SET title=?, content=?, category=?, source=?,
                    verification_status=?, approval_status=?, confidence=?,
                    version=?, tags=?, updated_at=?
                WHERE id=?
                """,
                (
                    title, content, category, source, verification, approval,
                    confidence, next_version, tags_json, now, knowledge_id,
                ),
            )
            version_record = {
                "title": title,
                "content": content,
                "category": category,
                "source": source,
                "verification_status": verification,
                "approval_status": approval,
                "confidence": confidence,
                "tags": json.loads(tags_json),
            }
            self._record_knowledge_version(
                connection, knowledge_id, next_version, version_record,
                changed_by, change_reason, now,
            )
            row = connection.execute(
                "SELECT * FROM knowledge_records WHERE id = ?", (knowledge_id,)
            ).fetchone()
        return self._knowledge_row(row)

    def list_knowledge(self, status=None, category=None, limit=100):
        clauses = []
        params = []
        if status:
            clauses.append("approval_status = ?")
            params.append(status)
        if category:
            clauses.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM knowledge_records
                {where}
                ORDER BY updated_at DESC LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [self._knowledge_row(row) for row in rows]

    def search_knowledge(self, query, approved_only=True, limit=20):
        term = f"%{query.strip()}%"
        approval = "AND approval_status = 'approved'" if approved_only else ""
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM knowledge_records
                WHERE (title LIKE ? OR content LIKE ? OR tags LIKE ? OR category LIKE ?)
                {approval}
                ORDER BY updated_at DESC LIMIT ?
                """,
                (term, term, term, term, limit),
            ).fetchall()
        return [self._knowledge_row(row) for row in rows]

    def knowledge_history(self, knowledge_id):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM knowledge_versions
                WHERE knowledge_id = ? ORDER BY version DESC
                """,
                (knowledge_id,),
            ).fetchall()
        history = []
        for row in rows:
            item = dict(row)
            item["tags"] = json.loads(item["tags"])
            history.append(item)
        return history

    def get_knowledge(self, knowledge_id):
        with self.lock, self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM knowledge_records WHERE id = ?", (knowledge_id,)
            ).fetchone()
        return self._knowledge_row(row)

    def approve_knowledge(self, knowledge_id, changed_by="operator"):
        return self.update_knowledge(
            knowledge_id,
            {
                "approval_status": "approved",
                "verification_status": "verified",
            },
            changed_by,
            "approved",
        )

    def reject_knowledge(self, knowledge_id, changed_by="operator"):
        return self.update_knowledge(
            knowledge_id,
            {"approval_status": "rejected"},
            changed_by,
            "rejected",
        )

    def deprecate_knowledge(self, knowledge_id, changed_by="operator"):
        return self.update_knowledge(
            knowledge_id,
            {"approval_status": "deprecated"},
            changed_by,
            "deprecated",
        )

    def _knowledge_row(self, row):
        if row is None:
            return None
        item = dict(row)
        item["tags"] = json.loads(item["tags"])
        return item

    def _record_knowledge_version(
        self, connection, knowledge_id, version, record,
        changed_by, change_reason, changed_at
    ):
        connection.execute(
            """
            INSERT INTO knowledge_versions
            (knowledge_id, version, title, content, category, source,
             verification_status, approval_status, confidence, tags,
             changed_by, change_reason, changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                knowledge_id, version, record["title"], record["content"],
                record["category"], record["source"],
                record.get("verification_status", "unverified"),
                record.get("approval_status", "pending_review"),
                record.get("confidence", "low"),
                json.dumps(record.get("tags", [])), changed_by,
                change_reason, changed_at,
            ),
        )

    def create_feedback(self, feedback):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        proposed_knowledge_id = None
        correction_types = {
            "incorrect",
            "partially_correct",
            "root_cause_rejected",
            "recommendation_rejected",
            "user_correction",
        }
        with self.lock, self.connect() as connection:
            correction = (feedback.get("user_correction") or "").strip()
            if correction and feedback["feedback_type"] in correction_types:
                cursor = connection.execute(
                    """
                    INSERT INTO knowledge_records
                    (title, content, category, source, incident_id,
                     verification_status, approval_status, confidence, version,
                     tags, created_at, updated_at)
                    VALUES (?, ?, 'correction', 'feedback', ?, 'proposed',
                            'pending_review', 'low', 1, ?, ?, ?)
                    """,
                    (
                        f"User correction for incident {feedback.get('incident_id')}",
                        correction[:10000],
                        feedback.get("incident_id"),
                        json.dumps(["user-correction"]),
                        now,
                        now,
                    ),
                )
                proposed_knowledge_id = cursor.lastrowid
                self._record_knowledge_version(
                    connection,
                    proposed_knowledge_id,
                    1,
                    {
                        "title": f"User correction for incident {feedback.get('incident_id')}",
                        "content": correction[:10000],
                        "category": "correction",
                        "source": "feedback",
                        "verification_status": "proposed",
                        "approval_status": "pending_review",
                        "confidence": "low",
                        "tags": ["user-correction"],
                    },
                    "system",
                    "created from user feedback",
                    now,
                )
            cursor = connection.execute(
                """
                INSERT INTO investigation_feedback
                (incident_id, investigation_id, original_query, model_response_json,
                 model_version, prompt_version, retrieved_knowledge_ids,
                 feedback_type, user_correction, occurred_at, review_status,
                 proposed_knowledge_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)
                """,
                (
                    feedback.get("incident_id"),
                    feedback.get("investigation_id"),
                    feedback.get("original_query", "")[:5000],
                    json.dumps(feedback.get("model_response") or {}),
                    feedback.get("model_version"),
                    feedback.get("prompt_version"),
                    json.dumps(feedback.get("retrieved_knowledge_ids", [])),
                    feedback["feedback_type"],
                    correction or None,
                    now,
                    proposed_knowledge_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM investigation_feedback WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        return self._feedback_row(row)

    def list_feedback(self, limit=100):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM investigation_feedback
                ORDER BY occurred_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._feedback_row(row) for row in rows]

    def feedback_analytics(self):
        with self.lock, self.connect() as connection:
            by_type = connection.execute(
                """
                SELECT feedback_type, COUNT(*) AS count
                FROM investigation_feedback GROUP BY feedback_type
                ORDER BY count DESC
                """,
            ).fetchall()
            pending_corrections = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM investigation_feedback
                WHERE review_status = 'pending_review'
                  AND user_correction IS NOT NULL
                """,
            ).fetchone()
            proposed = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM knowledge_records
                WHERE category = 'correction'
                  AND approval_status = 'pending_review'
                """,
            ).fetchone()
        return {
            "feedback_by_type": [dict(row) for row in by_type],
            "pending_correction_feedback": pending_corrections["count"],
            "pending_correction_knowledge": proposed["count"],
        }

    def review_feedback(self, feedback_id, review_status):
        if review_status not in {"reviewed", "rejected"}:
            raise ValueError("Unsupported feedback review status")
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE investigation_feedback
                SET review_status = ?
                WHERE id = ?
                """,
                (review_status, feedback_id),
            )
            row = connection.execute(
                "SELECT * FROM investigation_feedback WHERE id = ?",
                (feedback_id,),
            ).fetchone()
        return self._feedback_row(row) if row else None

    def _feedback_row(self, row):
        if row is None:
            return None
        item = dict(row)
        item["model_response"] = json.loads(item.pop("model_response_json"))
        item["retrieved_knowledge_ids"] = json.loads(
            item.pop("retrieved_knowledge_ids")
        )
        return item

    def store_evaluation_run(self, report):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO evaluation_runs
                (run_name, prompt_version, model_name, dataset_version,
                 report_json, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["run_name"], report["prompt_version"], report["model_name"],
                    report["dataset_version"], json.dumps(report),
                    report.get("started_at", now), now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM evaluation_runs WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
        item = dict(row)
        item["report"] = json.loads(item.pop("report_json"))
        return item

    def list_evaluation_runs(self, limit=50):
        with self.lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evaluation_runs
                ORDER BY completed_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        runs = []
        for row in rows:
            item = dict(row)
            item["report"] = json.loads(item.pop("report_json"))
            runs.append(item)
        return runs

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
        """Atomically claim one eligible queue item across threads/processes."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT id FROM investigations
                WHERE (status = 'pending' OR (status = 'failed' AND attempts < ?))
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY id ASC LIMIT 1
                """,
                (max_attempts, now),
            ).fetchone()
            if row is None:
                return None
            cursor = connection.execute(
                """
                UPDATE investigations
                SET status = 'processing', attempts = attempts + 1, error_details = NULL,
                    updated_at = ?
                WHERE id = ?
                  AND (status = 'pending' OR (status = 'failed' AND attempts < ?))
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                """,
                (now, row["id"], max_attempts, now),
            )
            if cursor.rowcount != 1:
                return None
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