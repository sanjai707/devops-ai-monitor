import json
import unittest
from pathlib import Path

from ai_investigator import IncidentInvestigator, _format_inspection_exit_137_fact
from evaluation import run_evaluation


class Phase15QualityTests(unittest.TestCase):
    def setUp(self):
        self.investigator = IncidentInvestigator.__new__(IncidentInvestigator)

    def validate(self, claim, inventory, classification="confirmed_fact", references=None):
        result = self.investigator._validate_result({
            "summary": "Fixture result",
            "root_cause": "Insufficient evidence to determine the root cause.",
            "confidence": "high",
            "findings": [{
                "claim": claim,
                "classification": classification,
                "supporting_evidence_ids": references if references is not None else [item["id"] for item in inventory],
                "contradictory_evidence_ids": [],
            }],
        }, inventory)
        return result

    def test_oom_false_downgrades_positive_oom_claim(self):
        inventory = [{
            "id": "INS-001", "source_type": "inspection", "status": "collected",
            "payload": {"exit_code": 137, "oom_killed": False},
        }]
        result = self.validate("The container was OOM-killed.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")
        self.assertIn("INS-001", result["findings"][0]["contradictory_evidence_ids"])

    def test_oom_true_and_event_support_confirmed_oom_observation(self):
        inventory = [
            {"id": "INS-001", "source_type": "inspection", "status": "collected",
             "payload": {"exit_code": 137, "oom_killed": True}},
            {"id": "EVT-001", "source_type": "docker_event", "status": "collected",
             "payload": {"action": "oom", "attributes": {"exitCode": "137"}}},
        ]
        result = self.validate(
            "The container was OOM-killed.", inventory,
            classification="probable_explanation",
        )
        self.assertEqual(result["findings"][0]["classification"], "confirmed_fact")
        self.assertIn("Confirmed Docker-observed OOM termination", result["root_cause"])
        self.assertEqual(result["confidence"], "medium")

    def test_exit_code_mismatch_is_not_confirmed(self):
        inventory = [{
            "id": "INS-001", "source_type": "inspection", "status": "collected",
            "payload": {"status": "exited", "exit_code": 143},
        }]
        result = self.validate("The container exited with code 137.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")
        self.assertIn("INS-001", result["findings"][0]["contradictory_evidence_ids"])

    def test_metrics_without_state_do_not_prove_container_running(self):
        inventory = [{
            "id": "MET-001", "source_type": "metric", "status": "collected",
            "payload": {"cpu_percent": 12, "memory_percent": 20},
        }]
        result = self.validate("The container is running.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")

    def test_health_status_must_match_docker_observation(self):
        inventory = [{
            "id": "INS-001", "source_type": "inspection", "status": "collected",
            "payload": {"status": "running", "health_status": "healthy"},
        }]
        result = self.validate("The container health status is unhealthy.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")
        self.assertIn("INS-001", result["findings"][0]["contradictory_evidence_ids"])

    def test_low_cpu_measurement_contradicts_saturation_claim(self):
        inventory = [{
            "id": "MET-001", "source_type": "metric", "status": "collected",
            "payload": {"cpu_percent": 15},
        }]
        result = self.validate("CPU utilization was saturated.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")

    def test_operator_annotation_is_not_independent_confirmation(self):
        inventory = [{
            "id": "ACT-001", "source_type": "operator_action", "status": "collected",
            "payload": {"action": "stop", "result": "succeeded", "source": "operator_annotation"},
        }]
        result = self.validate("The operator intentionally stopped the container.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "probable_explanation")

    def test_scalar_operator_result_is_not_parsed_as_nested_docker_events(self):
        inventory = [{
            "id": "ACT-001", "source_type": "operator_action", "status": "collected",
            "payload": {
                "action": "stop",
                "result": "succeeded",
                "source": "operator_annotation",
                "context": "A test-harness stop",
            },
        }]
        result = self.validate(
            "The container was intentionally stopped by an operator.",
            inventory,
        )
        self.assertEqual(result["findings"][0]["classification"], "probable_explanation")
        self.assertEqual(result["confidence"], "low")

    def test_docker_die_event_does_not_prove_operator_intent(self):
        inventory = [{
            "id": "EVT-001", "source_type": "docker_event", "status": "collected",
            "payload": {"action": "die", "attributes": {"exitCode": "143"}},
        }]
        result = self.validate("An operator intentionally stopped the container.", inventory)
        self.assertEqual(result["findings"][0]["classification"], "hypothesis")

    def test_missing_inspection_state_is_not_rendered_as_none(self):
        self.assertNotIn("None", _format_inspection_exit_137_fact({"exit_code": 137, "oom_killed": False}))
        self.assertIn("reported state 'exited'", _format_inspection_exit_137_fact({
            "status": "exited", "exit_code": 137, "oom_killed": False,
        }))

    def test_dataset_has_thirty_cases_and_deterministic_rules_pass(self):
        dataset_path = Path(__file__).resolve().parents[1] / "evaluation" / "evaluation_cases.json"
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        self.assertEqual(len(dataset["cases"]), 30)
        self.assertTrue(all(case.get("review_criteria") for case in dataset["cases"]))

        self.investigator.model_name = "deterministic-fixture"
        report = run_evaluation(self.investigator)
        self.assertEqual(report["total"], 30)
        self.assertEqual(report["passed"], 30, report["cases"])
        self.assertEqual(report["failed"], 0)
        self.assertIsNone(report["root_cause_accuracy"])
        self.assertGreater(report["validator_quality_metrics"]["downgraded_findings"], 0)
        self.assertGreater(report["validator_quality_metrics"]["omitted_findings"], 0)


if __name__ == "__main__":
    unittest.main()
