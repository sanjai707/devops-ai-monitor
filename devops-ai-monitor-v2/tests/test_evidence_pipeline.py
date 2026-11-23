import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_investigator import IncidentInvestigator, InvestigationError
from database import IncidentDatabase
from docker_event_collector import DockerEventCollector
from monitor import DockerMonitor
from evaluation import run_evaluation
from providers import DockerProvider


class EventDatabase:
    def __init__(self):
        self.events = []

    def store_docker_event(self, event):
        self.events.append(event)
        return True


class EvidencePipelineTests(unittest.TestCase):
    def test_docker_provider_reports_unavailable_without_crashing(self):
        provider = DockerProvider()
        with patch("providers.docker_provider.docker.from_env", side_effect=RuntimeError("daemon unavailable")):
            status = provider.status()
        self.assertEqual(status["provider"], "docker")
        self.assertFalse(status["connected"])
        self.assertEqual(status["error"], "RuntimeError")

    def test_repeatable_evaluation_dataset(self):
        investigator = IncidentInvestigator.__new__(IncidentInvestigator)
        investigator.model_name = "qwen2.5:3b"
        report = run_evaluation(investigator)
        self.assertGreaterEqual(report["total"], 10)
        self.assertGreaterEqual(report["passed"], 10)

    def test_feedback_correction_requires_review_before_knowledge(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            database = IncidentDatabase(str(Path(directory) / "incidents.db"))
            feedback = database.create_feedback({
                "incident_id": 10,
                "investigation_id": 18,
                "original_query": "Investigate incident 10",
                "model_response": {"root_cause": "unknown"},
                "model_version": "qwen2.5:3b",
                "prompt_version": "evidence-grounded-v1",
                "retrieved_knowledge_ids": [1],
                "feedback_type": "user_correction",
                "user_correction": "The container was intentionally stopped by a controlled test.",
            })
            self.assertEqual(feedback["review_status"], "pending_review")
            self.assertIsNotNone(feedback["proposed_knowledge_id"])
            proposed = database.get_knowledge(feedback["proposed_knowledge_id"])
            self.assertEqual(proposed["approval_status"], "pending_review")
            self.assertEqual(database.search_knowledge("controlled test", approved_only=True), [])
            analytics = database.feedback_analytics()
            self.assertEqual(analytics["pending_correction_feedback"], 1)
            reviewed = database.review_feedback(feedback["id"], "reviewed")
            self.assertEqual(reviewed["review_status"], "reviewed")

    def test_knowledge_lifecycle_and_search_require_approval(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            database = IncidentDatabase(str(Path(directory) / "incidents.db"))
            record = database.create_knowledge({
                "title": "Container restart runbook",
                "content": "Review restart policy and logs before restarting.",
                "category": "runbook",
                "source": "operator",
                "incident_id": None,
                "verification_status": "unverified",
                "approval_status": "pending_review",
                "confidence": "medium",
                "tags": ["restart", "docker"],
            })
            self.assertEqual(record["approval_status"], "pending_review")
            self.assertEqual(database.search_knowledge("restart", approved_only=True), [])
            approved = database.approve_knowledge(record["id"], "reviewer")
            self.assertEqual(approved["approval_status"], "approved")
            self.assertEqual(approved["verification_status"], "verified")
            results = database.search_knowledge("restart", approved_only=True)
            self.assertEqual(results[0]["id"], record["id"])
            history = database.knowledge_history(record["id"])
            self.assertGreaterEqual(len(history), 2)
            rejected = database.reject_knowledge(record["id"], "reviewer")
            self.assertEqual(rejected["approval_status"], "rejected")
            self.assertEqual(database.search_knowledge("restart", approved_only=True), [])

    def test_incident_lifecycle_is_audited_and_occurrences_are_counted(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            database = IncidentDatabase(str(Path(directory) / "incidents.db"))
            incident = database.create({
                "fingerprint": "lifecycle-test",
                "container_id": "container-full-id",
                "container_name": "sample",
                "type": "cpu_usage",
                "severity": "warning",
                "title": "High CPU",
                "status": "open",
                "evidence": {"cpu_percent": 90},
                "created_at": "2026-11-21T10:00:00Z",
                "updated_at": "2026-11-21T10:00:00Z",
            })
            incident = database.update(
                incident["id"], "critical", "Critical CPU",
                {"cpu_percent": 96}, "2026-11-21T10:00:10Z"
            )
            self.assertEqual(incident["event_count"], 2)
            self.assertEqual(incident["first_seen_at"], "2026-11-21T10:00:00Z")
            incident = database.update_status(
                incident["id"], "acknowledged", "2026-11-21T10:01:00Z"
            )
            incident = database.update_status(
                incident["id"], "investigating", "2026-11-21T10:02:00Z"
            )
            incident = database.update_status(
                incident["id"], "resolved", "2026-11-21T10:03:00Z"
            )
            incident = database.update_status(
                incident["id"], "reopened", "2026-11-21T10:04:00Z"
            )
            incident = database.add_incident_comment(
                incident["id"], "CPU returned; operator review required", "sre"
            )
            audit = database.list_incident_audit(incident["id"])
            actions = [item["action"] for item in audit]
            self.assertIn("created", actions)
            self.assertIn("status_changed", actions)
            self.assertIn("comment", actions)
            self.assertGreaterEqual(len(audit), 6)
            self.assertEqual(incident["status"], "reopened")

    def test_sqlite_event_deduplication_and_metric_window(self):
        with tempfile.TemporaryDirectory() as directory:
            database = IncidentDatabase(str(Path(directory) / "incidents.db"))
            event = {
                "event_id": "event-1",
                "event_time": "2026-11-21T10:00:00Z",
                "collected_at": "2026-11-21T10:00:01Z",
                "container_id": "container-full-id",
                "container_name": "sample",
                "action": "die",
                "attributes": {"exitCode": "137"},
            }
            self.assertTrue(database.store_docker_event(event))
            self.assertFalse(database.store_docker_event(event))
            database.record_metric_sample({
                "container_id": "container-full-id",
                "container_name": "sample",
                "observed_at": "2026-11-21T10:00:05Z",
                "cpu_percent": 12.5,
                "memory_usage_bytes": 100,
                "memory_limit_bytes": 1000,
                "memory_percent": 10.0,
                "network_rx_bytes": 300,
                "network_tx_bytes": 400,
                "running": False,
                "restart_count": 1,
                "health_status": None,
            })
            database.record_metric_sample({
                "container_id": "container-full-id",
                "container_name": "sample",
                "observed_at": "2026-11-21T10:00:06Z",
                "cpu_percent": 15.5,
                "memory_usage_bytes": 150,
                "memory_limit_bytes": 1000,
                "memory_percent": 15.0,
                "network_rx_bytes": 1300,
                "network_tx_bytes": 2400,
                "running": False,
                "restart_count": 1,
                "health_status": None,
            })
            events, metrics = database.evidence_window(
                "container", "2026-11-21T09:59:00Z", "2026-11-21T10:01:00Z"
            )
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["attributes"]["exitCode"], "137")
            self.assertEqual(len(metrics), 2)
            self.assertEqual(metrics[0]["cpu_percent"], 12.5)
            self.assertEqual(metrics[1]["network_rx_rate_bytes_per_sec"], 1000.0)
            self.assertEqual(metrics[1]["network_tx_rate_bytes_per_sec"], 2000.0)
            database.create({
                "fingerprint": "test",
                "container_id": "container-full-id",
                "container_name": "sample",
                "type": "container_stopped",
                "severity": "warning",
                "title": "Sample stopped",
                "status": "open",
                "evidence": {},
                "created_at": "2026-11-21T10:00:00Z",
                "updated_at": "2026-11-21T10:00:00Z",
            })
            action = database.store_operator_action({
                "incident_id": 1,
                "container_id": "container-full-id",
                "action": "stop",
                "action_result": "succeeded",
                "actor": "test",
                "context": "Controlled stop test",
                "source": "test_harness",
                "occurred_at": "2026-11-21T10:00:10Z",
                "collected_at": "2026-11-21T10:00:11Z",
            })
            self.assertEqual(action["source"], "test_harness")
            self.assertEqual(
                len(database.operator_actions_in_window(
                    1, "2026-11-21T09:59:00Z", "2026-11-21T10:01:00Z"
                )),
                1,
            )

    def test_monitor_records_cumulative_metrics_without_separate_poll(self):
        with tempfile.TemporaryDirectory() as directory:
            database = IncidentDatabase(str(Path(directory) / "incidents.db"))

            class Container:
                id = "container-full-id"
                name = "sample"
                short_id = "container"

            monitor = DockerMonitor(database)
            monitor._record_metric_sample(
                Container(), "running", 2, "healthy", {
                    "cpu_percent": 81.0,
                    "memory_usage_bytes": 900,
                    "memory_limit_bytes": 1000,
                    "memory_percent": 90.0,
                    "network_rx_bytes": 1234,
                    "network_tx_bytes": 5678,
                }
            )
            _, metrics = database.evidence_window(
                "container", "2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"
            )
            self.assertEqual(len(metrics), 1)
            self.assertEqual(metrics[0]["network_rx_bytes"], 1234)
            self.assertEqual(metrics[0]["running"], 1)
            self.assertEqual(metrics[0]["restart_count"], 2)

    def test_docker_event_normalization_filters_attributes_and_deduplicates(self):
        database = EventDatabase()
        collector = DockerEventCollector(database)
        raw_event = {
            "Type": "container",
            "Action": "die",
            "time": 1795255200,
            "timeNano": 1795255200000000000,
            "Actor": {
                "ID": "container-full-id",
                "Attributes": {
                    "name": "sample",
                    "image": "sample:latest",
                    "exitCode": "137",
                    "secret": "must-not-be-recorded",
                },
            },
        }
        self.assertTrue(collector._store_event(raw_event))
        event = database.events[0]
        self.assertEqual(event["action"], "die")
        self.assertNotIn("secret", event["attributes"])
        self.assertEqual(event["attributes"]["exitCode"], "137")
        self.assertEqual(len(event["event_id"]), 64)

    def test_validator_downgrades_unsupported_oom_cause_and_unknown_evidence(self):
        investigator = IncidentInvestigator.__new__(IncidentInvestigator)
        inventory = [{
            "id": "INS-001",
            "source_type": "inspection",
            "status": "collected",
            "payload": {"exit_code": 137, "oom_killed": False},
        }]
        result = investigator._validate_result({
            "root_cause": "The process was killed by OOM",
            "summary": "The process was killed by OOM",
            "confidence": "high",
            "findings": [
                {
                    "claim": "The process was killed by OOM",
                    "classification": "probable_explanation",
                    "supporting_evidence_ids": ["INS-001", "NOT-REAL"],
                    "contradictory_evidence_ids": [],
                },
                {
                    "claim": "An unrelated network failure occurred",
                    "classification": "confirmed_fact",
                    "supporting_evidence_ids": ["NOT-REAL"],
                    "contradictory_evidence_ids": [],
                },
            ],
        }, inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")
        self.assertEqual(result["findings"][0]["contradictory_evidence_ids"], ["INS-001"])
        self.assertEqual(result["root_cause"], "Insufficient evidence to determine the root cause.")
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["supporting_evidence_ids"], ["INS-001"])

    def test_validator_rejects_malformed_types_and_drops_uncited_recommendations(self):
        investigator = IncidentInvestigator.__new__(IncidentInvestigator)
        with self.assertRaisesRegex(InvestigationError, "confidence"):
            investigator._validate_result({"confidence": False})

        result = investigator._validate_result({
            "read_only_checks": [{
                "description": "Review logs",
                "reason": "Look for errors",
                "evidence_ids": ["UNKNOWN"],
                "expected_impact": "More context",
                "risk_level": "low",
                "required_approval": False,
                "verification_steps": ["Review output"],
                "rollback_considerations": "Not applicable",
            }]
        }, [])
        self.assertEqual(result["read_only_checks"], [])
        self.assertTrue(any("Recommendation omitted" in item for item in result["missing_information"]))

    def test_exit_137_investigation_keeps_intent_unknown_and_adds_safe_checks(self):
        response_body = {
            "response": (
                '{"summary":"The operator stopped the container due to OOM",'
                '"root_cause":"The operator stopped the container due to OOM",'
                '"confidence":"high","findings":['
                '{"claim":"The container was unexpectedly stopped due to OOM",'
                '"classification":"confirmed_fact","supporting_evidence_ids":["INC-001"],'
                '"contradictory_evidence_ids":[]},'
                '{"claim":"The process may have received SIGKILL",'
                '"classification":"probable_explanation","supporting_evidence_ids":["INS-001"],'
                '"contradictory_evidence_ids":[]}]}'
            )
        }

        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return response_body

        class FakeClient:
            def __init__(self, **kwargs):
                return None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def post(self, *args, **kwargs):
                return FakeResponse()

        investigator = IncidentInvestigator.__new__(IncidentInvestigator)
        investigator.ollama_url = "http://ollama"
        investigator.model_name = "qwen2.5:3b"
        investigator.request_timeout = 30
        evidence = {
            "incident": {
                "id": 10,
                "title": "Container test stopped unexpectedly",
                "recorded_evidence": {"exit_code": 137, "oom_killed": False},
            },
            "inspection": {
                "status": "exited",
                "exit_code": 137,
                "oom_killed": False,
            },
            "evidence_inventory": [
                {
                    "id": "INC-001",
                    "source_type": "incident",
                    "status": "collected",
                    "payload": {
                        "recorded_evidence": {"exit_code": 137, "oom_killed": False}
                    },
                },
                {
                    "id": "INS-001",
                    "source_type": "inspection",
                    "status": "collected",
                    "payload": {"exit_code": 137, "oom_killed": False},
                },
                {
                    "id": "EVT-003",
                    "source_type": "docker_event",
                    "status": "unavailable",
                    "payload": {},
                },
            ],
            "timeline": [],
            "missing_information": ["Docker events are unavailable."],
            "collection_errors": [],
        }
        with patch("ai_investigator.httpx.Client", FakeClient):
            report = investigator._request_investigation(evidence)
        self.assertEqual(report["root_cause"], "Insufficient evidence to determine the root cause.")
        self.assertEqual(report["confidence"], "low")
        self.assertTrue(any("intent remains unknown" in item for item in report["missing_information"]))
        self.assertTrue(any("Review Docker daemon events" in item for item in report["recommended_checks"]))
        self.assertTrue(any("SIGKILL" in item for item in report["hypotheses"]))
        self.assertFalse(any(
            item["classification"] == "confirmed_fact" and "unexpected" in item["claim"].lower()
            for item in report["findings"]
        ))
        annotated = copy.deepcopy(evidence)
        annotated["inspection"]["finished_at"] = "2026-11-21T15:34:14.695Z"
        annotated["evidence_inventory"].append({
            "id": "ACT-004",
            "source_type": "operator_action",
            "status": "collected",
            "event_timestamp": "2026-11-21T15:34:10Z",
            "payload": {
                "action": "stop",
                "result": "succeeded",
                "source": "test_harness",
                "context": "Controlled test stop",
            },
        })
        with patch("ai_investigator.httpx.Client", FakeClient):
            annotated_report = investigator._request_investigation(annotated)
        self.assertIn("test_harness", annotated_report["root_cause"])
        self.assertNotEqual(
            annotated_report["root_cause"],
            "Insufficient evidence to determine the root cause.",
        )
        self.assertFalse(any(
            item["classification"] == "confirmed_fact" and "unexpected" in item["claim"].lower()
            for item in annotated_report["findings"]
        ))


if __name__ == "__main__":
    unittest.main()
