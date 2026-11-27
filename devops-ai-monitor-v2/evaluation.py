import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from ai_investigator import IncidentInvestigator, InvestigationError, redact_log_secrets


DATASET_PATH = Path(__file__).parent / "evaluation" / "evaluation_cases.json"


def run_evaluation(investigator, run_name="baseline", prompt_version="evidence-grounded-v1"):
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    results = []
    passed = 0
    started_at = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    for case in dataset["cases"]:
        result = {
            "id": case["id"],
            "passed": False,
            "error": None,
        }
        try:
            validated = investigator._validate_result(
                case["model_output"], case["evidence_inventory"]
            )
            expected = case["expect"]
            checks = []
            evidence_ids = {
                item["id"]
                for item in case["evidence_inventory"]
                if item.get("status") == "collected"
            }
            cited_ids = set()
            unsupported = 0
            for finding in validated.get("findings", []):
                cited = set(finding.get("supporting_evidence_ids", []))
                cited_ids.update(cited)
                unsupported += int(bool(cited - evidence_ids))
            evidence_reference_accuracy = (
                (len(cited_ids) - len(cited_ids - evidence_ids)) / len(cited_ids)
                if cited_ids else 1.0
            )
            result["evidence_reference_accuracy"] = round(evidence_reference_accuracy, 4)
            result["unsupported_claim_count"] = unsupported
            if "confidence" in expected:
                checks.append(validated["confidence"] == expected["confidence"])
            if expected.get("root_cause_insufficient"):
                checks.append(
                    validated["root_cause"] == "Insufficient evidence to determine the root cause."
                )
            if expected.get("unsupported_claim_removed"):
                checks.append(
                    not any(
                        finding["claim"] == "Network failure occurred"
                        for finding in validated["findings"]
                    )
                )
            if expected.get("classification_not_confirmed"):
                classifications = [
                    finding["classification"] for finding in validated["findings"]
                ]
                checks.append("confirmed_fact" not in classifications)
            if expected.get("classification_confirmed"):
                checks.append(
                    any(
                        finding["classification"] == "confirmed_fact"
                        for finding in validated["findings"]
                    )
                )
            if expected.get("contradiction_present"):
                checks.append(
                    any(
                        finding["contradictory_evidence_ids"]
                        for finding in validated["findings"]
                    )
                )
            if expected.get("recommendation_removed"):
                checks.append(not validated.get("read_only_checks"))
            if expected.get("must_reject"):
                checks.append(False)
            result["passed"] = bool(checks) and all(checks)
            result["output"] = {
                "confidence": validated["confidence"],
                "root_cause": validated["root_cause"],
                "findings": validated["findings"],
            }
        except InvestigationError as exc:
            if case["expect"].get("must_reject"):
                result["passed"] = True
                result["error"] = str(exc)
            else:
                result["error"] = str(exc)
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        if result["passed"]:
            passed += 1
        results.append(result)

    return {
        "run_name": run_name,
        "prompt_version": prompt_version,
        "model_name": investigator.model_name,
        "dataset_version": dataset["dataset_version"],
        "started_at": started_at,
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "pass_rate": round(passed / len(results), 4) if results else 0.0,
        "evidence_reference_accuracy": round(
            sum(item.get("evidence_reference_accuracy", 0.0) for item in results)
            / len(results),
            4,
        ) if results else 0.0,
        "unsupported_claim_rate": round(
            sum(item.get("unsupported_claim_count", 0) for item in results)
            / sum(
                len(finding.get("supporting_evidence_ids", []))
                for item in results
                for finding in item.get("output", {}).get("findings", [])
            ),
            4,
        ) if sum(
            len(finding.get("supporting_evidence_ids", []))
            for item in results
            for finding in item.get("output", {}).get("findings", [])
        ) else 0.0,
        # The current dataset has no independently adjudicated root-cause labels.
        # Do not present validator pass rate as root-cause accuracy.
        "root_cause_accuracy": None,
        "root_cause_scored_cases": 0,
        "root_cause_accuracy_status": "not_measured_no_adjudicated_labels",
        "confidence_calibration": {
            "high": sum(
                1 for item in results
                if item.get("output", {}).get("confidence") == "high"
            ),
            "medium": sum(
                1 for item in results
                if item.get("output", {}).get("confidence") == "medium"
            ),
            "low": sum(
                1 for item in results
                if item.get("output", {}).get("confidence") == "low"
            ),
        },
        "cases": results,
    }

def run_live_model_evaluation(
    investigator, case_ids=None, max_cases=5, run_name="local-ollama-review"
):
    """Run real model inference on curated evidence fixtures for human review.

    This intentionally does not compute root-cause accuracy: the current fixtures
    do not contain independently adjudicated root-cause labels.
    """
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    selected = [
        case for case in dataset["cases"]
        if not case.get("expect", {}).get("must_reject")
        and (not case_ids or case["id"] in set(case_ids))
    ][:max(1, min(int(max_cases), 12))]
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = []

    for case in selected:
        inventory = deepcopy(case["evidence_inventory"])
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        inspection_item = next(
            (
                item for item in inventory
                if item.get("source_type") == "inspection"
                and item.get("status") == "collected"
            ),
            None,
        )
        recorded_item = next(
            (
                item for item in inventory
                if item.get("source_type") == "incident"
                and item.get("status") == "collected"
            ),
            None,
        )
        inspection = (inspection_item or {}).get("payload") or {}
        recorded_evidence = (
            ((recorded_item or {}).get("payload") or {}).get("recorded_evidence")
            or inspection
        )
        missing = [
            f"{item.get('source_type', 'evidence')} is {item.get('status', 'unavailable')} in this fixture."
            for item in inventory
            if item.get("status") != "collected"
        ]
        container_id = next(
            (item.get("container_id") for item in inventory if item.get("container_id")),
            "evaluation-fixture-container",
        )
        timeline = [
            {
                "timestamp": item.get("event_timestamp"),
                "evidence_id": item.get("id"),
                "source_type": item.get("source_type", "unknown"),
                "description": f"Fixture evidence: {item.get('source_type', 'unknown')}",
            }
            for item in inventory
        ]
        evidence = {
            "incident": {
                "id": case["id"],
                "title": f"Curated model evaluation: {case['id']}",
                "type": "evaluation_fixture",
                "severity": "info",
                "created_at": now,
                "recorded_evidence": recorded_evidence,
            },
            "container": {"id": container_id, "name": "evaluation-fixture"},
            "window": {"start": now, "end": now},
            "inspection": inspection,
            "diagnostics": inspection,
            "metrics": None,
            "metric_history": [],
            "docker_events": [],
            "operator_actions": [],
            "recent_logs": "",
            "collection_errors": [],
            "missing_information": missing,
            "evidence_inventory": inventory,
            "timeline": timeline,
        }
        try:
            report = investigator._request_investigation(evidence)
            results.append({
                "case_id": case["id"],
                "status": "completed",
                "confidence": report.get("confidence"),
                "root_cause_assessment": report.get("root_cause"),
                "summary": report.get("summary"),
                "findings": report.get("findings", []),
                "missing_information": report.get("missing_information", []),
                "read_only_followups_proposed": [
                    item.get("followup_action_id")
                    for item in report.get("read_only_checks", [])
                    if item.get("followup_action_id")
                ],
                "evidence_inventory": report.get("evidence_inventory", []),
            })
        except Exception as exc:
            results.append({
                "case_id": case["id"],
                "status": "failed",
                "error": redact_log_secrets(
                    f"{type(exc).__name__}: {exc}"
                )[:500],
            })

    return {
        "run_name": run_name,
        "evaluation_mode": "real_model_inference_human_review",
        "model_name": investigator.model_name,
        "dataset_version": dataset["dataset_version"],
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "selected_cases": len(selected),
        "completed_cases": sum(item["status"] == "completed" for item in results),
        "failed_cases": sum(item["status"] == "failed" for item in results),
        "root_cause_accuracy": None,
        "root_cause_accuracy_status": "not_scored_no_independently_adjudicated_labels",
        "review_note": (
            "These are actual model outputs against curated evidence fixtures. "
            "Review each result; do not interpret completion, confidence, or the "
            "deterministic validator pass rate as root-cause accuracy."
        ),
        "cases": results,
    }
