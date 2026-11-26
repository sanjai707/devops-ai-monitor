import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import database as database_module
from database import IncidentDatabase
from ai_investigator import redact_structured_data
from followup_collector import collect_approved_read_only_followup
from evaluation import run_live_model_evaluation


class FakeContainer:
    id = "container-full-id"
    name = "sample"
    status = "exited"

    def reload(self):
        return None

    def logs(self, **kwargs):
        self.log_args = kwargs
        return b'2026-11-26T10:00:00Z password=topsecret application failed\n'


class FakeClient:
    def __init__(self, container=None):
        self.container = container or FakeContainer()
        self.closed = False
        self.event_args = None

    class ContainerCollection:
        def __init__(self, parent):
            self.parent = parent

        def get(self, container_id):
            if container_id not in ("container-full-id", "sample"):
                import docker
                raise docker.errors.NotFound("missing")
            return self.parent.container

    @property
    def containers(self):
        return self.ContainerCollection(self)

    def events(self, **kwargs):
        self.event_args = kwargs
        return iter([
            {
                "Type": "container",
                "Action": "die",
                "time": 1795687200,
                "timeNano": 1795687200000000000,
                "Actor": {
                    "ID": "container-full-id",
                    "Attributes": {
                        "name": "sample",
                        "image": "https://registry-user:registry-pass@registry.example/busybox:latest",
                        "exitCode": "137",
                        "password": "must-not-be-included",
                    },
                },
            }
        ])

    def close(self):
        self.closed = True


def incident_record():
    return {
        "fingerprint": "followup-test",
        "container_id": "container-full-id",
        "container_name": "sample",
        "type": "container_stopped",
        "severity": "warning",
        "title": "Container stopped",
        "status": "open",
        "evidence": {"exit_code": 137, "oom_killed": False},
        "created_at": "2026-11-26T10:00:00Z",
        "updated_at": "2026-11-26T10:00:00Z",
    }


class FollowupWorkflowTests(unittest.TestCase):
    def test_structured_redaction_removes_secret_fields_and_redacts_string_values(self):
        source = {
            "status": "failed",
            "api_key": "structured-secret",
            "nested": {
                "Authorization": "Bearer abc.def.ghi",
                "message": "password=inline-secret",
                "safe": "no sensitive data",
            },
        }
        redacted = redact_structured_data(source)
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["Authorization"], "[REDACTED]")
        self.assertNotIn("structured-secret", repr(redacted))
        self.assertNotIn("abc.def.ghi", repr(redacted))
        self.assertNotIn("inline-secret", repr(redacted))
        self.assertEqual(redacted["nested"]["safe"], "no sensitive data")

    def test_only_allowlisted_read_only_actions_are_supported(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            collect_approved_read_only_followup(
                FakeClient(), FakeContainer(), "docker.exec", 100, 200
            )

    def test_event_collection_is_container_scoped_and_attribute_allowlisted(self):
        client = FakeClient()
        result = collect_approved_read_only_followup(
            client, client.container, "docker.container-events", 100, 200
        )
        self.assertEqual(result["item_count"], 1)
        self.assertEqual(result["events"][0]["action"], "die")
        self.assertIn("[REDACTED]@registry.example", result["events"][0]["attributes"]["image"])
        self.assertNotIn("registry-pass", repr(result))
        self.assertEqual(
            set(result["events"][0]["attributes"]),
            {"name", "image", "exitCode"},
        )
        self.assertEqual(client.event_args["filters"]["container"], ["container-full-id"])
        self.assertEqual(client.event_args["since"], 100)
        self.assertEqual(client.event_args["until"], 200)

    def test_log_collection_is_time_bounded_limited_and_redacted(self):
        container = FakeContainer()
        result = collect_approved_read_only_followup(
            FakeClient(container), container, "docker.container-logs", 100, 200
        )
        self.assertEqual(container.log_args["since"], 100)
        self.assertEqual(container.log_args["until"], 200)
        self.assertEqual(container.log_args["tail"], 300)
        self.assertNotIn("topsecret", result["lines"][0])
        self.assertIn("[REDACTED]", result["lines"][0])

    def test_model_followup_actions_are_allowlisted_and_evidence_linked(self):
        from ai_investigator import IncidentInvestigator

        investigator = IncidentInvestigator.__new__(IncidentInvestigator)
        inventory = [{
            "id": "INS-001",
            "source_type": "inspection",
            "status": "collected",
            "payload": {"status": "exited"},
        }]
        recommendation = {
            "description": "Review Docker events.",
            "reason": "Lifecycle evidence may add context.",
            "evidence_ids": ["INS-001"],
            "expected_impact": "Additional bounded context.",
            "risk_level": "low",
            "required_approval": False,
            "verification_steps": ["Compare timestamps."],
            "rollback_considerations": "Not applicable; read-only.",
        }
        report = investigator._validate_result({
            "read_only_checks": [
                {**recommendation, "followup_action_id": "docker.exec"},
                {**recommendation, "followup_action_id": "docker.container-events"},
            ],
            "corrective_actions": [
                {**recommendation, "followup_action_id": "docker.container-events"}
            ],
        }, inventory)
        self.assertIsNone(report["read_only_checks"][0]["followup_action_id"])
        self.assertEqual(
            report["read_only_checks"][1]["followup_action_id"],
            "docker.container-events",
        )
        self.assertIsNone(report["corrective_actions"][0]["followup_action_id"])

    def test_live_model_evaluation_reports_outputs_without_claiming_accuracy(self):
        class FakeInvestigator:
            model_name = "test-model"

            def _request_investigation(self, evidence):
                return {
                    "summary": "Fixture was reviewed by the test model.",
                    "root_cause": "Insufficient evidence to determine the root cause.",
                    "confidence": "low",
                    "findings": [],
                    "missing_information": ["More evidence is needed."],
                    "read_only_checks": [],
                    "evidence_inventory": evidence["evidence_inventory"],
                }

        report = run_live_model_evaluation(FakeInvestigator(), max_cases=1)
        self.assertEqual(report["evaluation_mode"], "real_model_inference_human_review")
        self.assertEqual(report["model_name"], "test-model")
        self.assertEqual(report["completed_cases"], 1)
        self.assertEqual(report["failed_cases"], 0)
        self.assertIsNone(report["root_cause_accuracy"])
        self.assertEqual(
            report["root_cause_accuracy_status"],
            "not_scored_no_independently_adjudicated_labels",
        )

    def test_followup_window_cannot_exceed_fifteen_minutes(self):
        with self.assertRaisesRegex(ValueError, "15-minute"):
            collect_approved_read_only_followup(
                FakeClient(), FakeContainer(), "docker.container-events", 0, 901
            )

    def test_database_persists_approval_collection_and_reassessment_link(self):
        with tempfile.TemporaryDirectory() as directory:
            db = IncidentDatabase(str(Path(directory) / "followup.db"))
            incident = db.create(incident_record())
            investigation, created = db.create_investigation(incident["id"])
            self.assertTrue(created)
            followup = db.create_investigation_followup({
                "incident_id": incident["id"],
                "source_investigation_id": investigation["id"],
                "container_id": incident["container_id"],
                "action_id": "docker.container-events",
                "request": {
                    "description": "Review lifecycle events.",
                    "evidence_ids": ["INS-001"],
                },
                "approved_by": "operator",
                "approved_at": "2026-11-26T10:01:00Z",
                "time_window": {"start": "2026-11-26T09:50:00Z"},
            })
            completed = db.complete_investigation_followup(
                followup["id"], {"events": []}, status="collected",
                limitations=["bounded sample"],
            )
            self.assertEqual(completed["status"], "collected")
            self.assertEqual(completed["result"], {"events": []})
            self.assertEqual(completed["limitations"], ["bounded sample"])
            self.assertEqual(
                completed["request"]["evidence_ids"], ["INS-001"]
            )
            reassessment, _ = db.create_investigation(incident["id"], force=True)
            db.link_followup_reassessment(followup["id"], reassessment["id"])
            stored = db.investigation_followups_for_incident(incident["id"])
            self.assertEqual(stored[0]["reassessment_investigation_id"], reassessment["id"])


    def test_followup_request_column_migrates_from_schema_seven(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "schema-seven.db")
            IncidentDatabase(path)
            connection = sqlite3.connect(path)
            connection.execute(
                "ALTER TABLE investigation_followups DROP COLUMN request_json"
            )
            connection.execute("PRAGMA user_version = 7")
            connection.commit()
            connection.close()

            migrated = IncidentDatabase(path)
            connection = sqlite3.connect(path)
            columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(investigation_followups)"
                ).fetchall()
            }
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.close()
            self.assertIn("request_json", columns)
            self.assertEqual(version, 8)
            self.assertEqual(migrated.investigation_followups_for_incident(1), [])

    def test_direct_analyze_redacts_logs_and_diagnostics_before_ollama(self):
        class AnalyzeFakeContainer(FakeContainer):
            short_id = "container-short"
            def logs(self, **kwargs):
                self.log_args = kwargs
                return "".join(
                    f"2026-11-26T10:00:{index % 60:02d}Z password=topsecret application event {index:04d} " + "x" * 80 + "\\n"
                    for index in range(350)
                ).encode("utf-8")

            attrs = {
                "State": {
                    "Status": "exited",
                    "Running": False,
                    "Paused": False,
                    "Restarting": False,
                    "Health": None,
                    "ExitCode": 143,
                    "OOMKilled": False,
                    "Error": "password=diagnostic-secret",
                    "StartedAt": "2026-11-26T09:55:00Z",
                    "FinishedAt": "2026-11-26T10:00:00Z",
                },
                "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
                "Config": {"Image": "busybox:latest"},
                "RestartCount": 2,
            }

        sent_payloads = []
        fake_client = FakeClient(AnalyzeFakeContainer())

        class FakeOllamaResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"response": "The container stopped; cause remains unconfirmed."}

        class FakeOllamaHTTPClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url, json, **kwargs):
                sent_payloads.append(json)
                return FakeOllamaResponse()

        previous_main = sys.modules.pop("main", None)
        previous_api_key = os.environ.get("API_KEY")
        os.environ["API_KEY"] = ""
        try:
            with patch.object(database_module, "IncidentDatabase", return_value=IncidentDatabase(":memory:")):
                with patch.dict(os.environ, {"API_KEY": ""}):
                    main_module = importlib.import_module("main")
            main_module.docker_client = lambda: fake_client
            client = TestClient(main_module.app)
            with patch.object(main_module.httpx, "Client", FakeOllamaHTTPClient):
                response = client.post(
                    "/analyze",
                    json={"container_id": "container-full-id", "tail": 1000},
                )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(fake_client.closed)
            self.assertEqual(fake_client.container.log_args["tail"], 300)
            self.assertEqual(len(sent_payloads), 1)
            prompt = sent_payloads[0]["prompt"]
            self.assertNotIn("topsecret", prompt)
            self.assertNotIn("diagnostic-secret", prompt)
            self.assertIn("[REDACTED]", prompt)
            body = response.json()
            self.assertNotIn("topsecret", response.text)
            self.assertEqual(body["analysis"], "The container stopped; cause remains unconfirmed.")
            self.assertEqual(body["diagnostics"]["error"], "password=[REDACTED]")
            self.assertTrue(body["model_input_summary"]["logs_redacted"])
            self.assertTrue(body["model_input_summary"]["diagnostics_redacted"])
            self.assertEqual(body["model_input_summary"]["log_line_limit"], 300)
            self.assertLessEqual(body["model_input_summary"]["log_bytes_included"], 20_000)
            self.assertLessEqual(body["model_input_summary"]["log_lines_included"], 300)
            self.assertTrue(body["model_input_summary"]["logs_truncated"])
            self.assertFalse(body["model_input_summary"]["container_environment_collected"])
            self.assertIn("error", body["model_input_summary"]["diagnostic_fields_included"])
        finally:
            sys.modules.pop("main", None)
            if previous_main is not None:
                sys.modules["main"] = previous_main
            if previous_api_key is None:
                os.environ.pop("API_KEY", None)
            else:
                os.environ["API_KEY"] = previous_api_key

    def test_api_requires_investigation_recommendation_and_records_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            db = IncidentDatabase(str(Path(directory) / "api-followup.db"))
            incident = db.create(incident_record())
            source, _ = db.create_investigation(incident["id"])
            report = {
                "summary": "Exit code is known; initiating action is not.",
                "root_cause": "Insufficient evidence to determine the root cause.",
                "confidence": "low",
                "read_only_checks": [{
                    "description": "Review Docker events.",
                    "followup_action_id": "docker.container-events",
                    "evidence_ids": ["INS-001"],
                    "reason": "Events may add context.",
                    "expected_impact": "Additional bounded lifecycle evidence.",
                    "risk_level": "low",
                    "required_approval": False,
                    "verification_steps": ["Compare event and incident times."],
                    "rollback_considerations": "Not applicable; read-only.",
                }],
            }
            report["evidence_inventory"] = [{
                "id": "INS-001",
                "source_type": "inspection",
                "status": "collected",
                "payload": {"exit_code": 137, "oom_killed": False},
            }]
            db.complete_investigation(source["id"], report, "qwen2.5:3b")
            fake_client = FakeClient()

            class FakeInvestigator:
                def enqueue(self, incident_id, force=False):
                    return db.create_investigation(incident_id, force=force)

            previous_main = sys.modules.pop("main", None)
            previous_api_key = os.environ.get("API_KEY")
            os.environ["API_KEY"] = ""
            try:
                with patch.object(database_module, "IncidentDatabase", return_value=db):
                    with patch.dict(os.environ, {"API_KEY": ""}):
                        main_module = importlib.import_module("main")
                main_module.incident_database = db
                main_module.incident_investigator = FakeInvestigator()
                main_module.docker_client = lambda: fake_client
                client = TestClient(main_module.app)
                rejected = client.post(
                    f"/incidents/{incident['id']}/investigation-followups",
                    json={
                        "source_investigation_id": source["id"],
                        "followup_action_id": "docker.container-logs",
                    },
                )
                self.assertEqual(rejected.status_code, 409)

                invalid_report = dict(report)
                invalid_report["read_only_checks"] = [
                    {**report["read_only_checks"][0], "evidence_ids": ["NOT-COLLECTED"]}
                ]
                db.complete_investigation(source["id"], invalid_report, "qwen2.5:3b")
                invalid_evidence = client.post(
                    f"/incidents/{incident['id']}/investigation-followups",
                    json={
                        "source_investigation_id": source["id"],
                        "followup_action_id": "docker.container-events",
                    },
                )
                self.assertEqual(invalid_evidence.status_code, 409)
                db.complete_investigation(source["id"], report, "qwen2.5:3b")

                response = client.post(
                    f"/incidents/{incident['id']}/investigation-followups",
                    json={
                        "source_investigation_id": source["id"],
                        "followup_action_id": "docker.container-events",
                        "approved_by": "operator",
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                body = response.json()
                self.assertTrue(body["approved"])
                self.assertTrue(body["reassessment_queued"])
                self.assertEqual(body["followup"]["status"], "collected")
                self.assertEqual(body["followup"]["container_id"], "container-full-id")
                self.assertEqual(
                    body["followup"]["request"]["evidence_ids"], ["INS-001"]
                )
                self.assertEqual(
                    body["followup"]["reassessment_investigation_id"],
                    body["reassessment"]["id"],
                )
                self.assertTrue(fake_client.closed)

                duplicate = client.post(
                    f"/incidents/{incident['id']}/investigation-followups",
                    json={
                        "source_investigation_id": source["id"],
                        "followup_action_id": "docker.container-events",
                    },
                )
                self.assertEqual(duplicate.status_code, 409)
            finally:
                sys.modules.pop("main", None)
                if previous_main is not None:
                    sys.modules["main"] = previous_main
                if previous_api_key is None:
                    os.environ.pop("API_KEY", None)
                else:
                    os.environ["API_KEY"] = previous_api_key


if __name__ == "__main__":
    unittest.main()
