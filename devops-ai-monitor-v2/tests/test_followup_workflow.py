import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import main
from database import IncidentDatabase
from followup_collector import collect_approved_read_only_followup


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
                        "image": "busybox:latest",
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
            db.complete_investigation(source["id"], report, "qwen2.5:3b")
            fake_client = FakeClient()

            class FakeInvestigator:
                def enqueue(self, incident_id, force=False):
                    return db.create_investigation(incident_id, force=force)

            with (
                patch.object(main, "incident_database", db),
                patch.object(main, "incident_investigator", FakeInvestigator()),
                patch.object(main, "docker_client", lambda: fake_client),
                patch.dict(os.environ, {"API_KEY": ""}),
            ):
                client = TestClient(main.app)
                rejected = client.post(
                    f"/incidents/{incident['id']}/investigation-followups",
                    json={
                        "source_investigation_id": source["id"],
                        "followup_action_id": "docker.container-logs",
                    },
                )
                self.assertEqual(rejected.status_code, 409)

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


if __name__ == "__main__":
    unittest.main()
