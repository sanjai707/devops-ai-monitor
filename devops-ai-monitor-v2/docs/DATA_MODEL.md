# Data Model Baseline

## Existing tables

- `incidents`: incident lifecycle, fingerprinting, severity, evidence, timestamps, acknowledgement and resolution.
- `investigations`: queue state, attempts, result fields, structured JSON, model, timestamps and failure details.

## Additive telemetry and intent tables

- `docker_events`: deduplicated, timestamped Docker lifecycle/event records.
- `metric_samples`: timestamped container CPU, memory, network, status, restart and health samples.
- `operator_actions`: explicitly supplied operator/test action annotations.
- `incident_audit`: incident lifecycle transitions and operator comments.
- `knowledge_records`: approved/pending knowledge and versioned operational lessons.
- `knowledge_versions`: immutable knowledge version snapshots.
- `investigation_feedback`: investigation feedback and proposed corrections.
- `evaluation_runs`: repeatable evaluation reports.

## Migration behavior

- Tables are created with `CREATE TABLE IF NOT EXISTS`.
- Existing records are not deleted during initialization.
- SQLite `PRAGMA user_version` is used for additive schema version tracking.
- Retention cleanup is bounded by configurable event/metric retention and row caps.
