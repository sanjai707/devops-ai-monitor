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
            "review_criteria": case.get("review_criteria", []),
        }
        try:
            raw_findings = case["model_output"].get("findings", [])
            evidence_inventory = case["evidence_inventory"]
            available_ids = {
                item["id"] for item in evidence_inventory
                if item.get("status") == "collected"
            }
            raw_references = [
                reference
                for finding in raw_findings if isinstance(finding, dict)
                for reference in (finding.get("supporting_evidence_ids") or [])
                if isinstance(reference, str)
            ]
            valid_reference_count = sum(
                reference in available_ids for reference in raw_references
            )
            unsupported_finding_count = sum(
                1 for finding in raw_findings
                if not isinstance(finding, dict)
                or not finding.get("supporting_evidence_ids")
                or any(
                    reference not in available_ids
                    for reference in finding.get("supporting_evidence_ids", [])
                )
            )
            validated = investigator._validate_result(
                case["model_output"], evidence_inventory
            )
            expected = case["expect"]
            checks = []
            raw_by_claim = {
                finding.get("claim"): finding.get("classification")
                for finding in raw_findings if isinstance(finding, dict)
            }
            downgraded_count = sum(
                1 for finding in validated.get("findings", [])
                if finding.get("claim") in raw_by_claim
                and finding.get("classification") != raw_by_claim[finding.get("claim")]
            )
            validated_claims = {
                finding.get("claim") for finding in validated.get("findings", [])
            }
            result["input_finding_count"] = len(raw_findings)
            result["retained_finding_count"] = len(validated_claims)
            result["omitted_finding_count"] = max(0, len(raw_findings) - len(validated_claims))
            result["unsupported_finding_count"] = unsupported_finding_count
            result["downgraded_finding_count"] = downgraded_count
            result["total_evidence_references"] = len(raw_references)
            result["valid_evidence_references"] = valid_reference_count
            result["evidence_reference_accuracy"] = (
                round(valid_reference_count / len(raw_references), 4)
                if raw_references else None
            )

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
            if expected.get("classification_probable"):
                checks.append(any(
                    finding["classification"] == "probable_explanation"
                    for finding in validated["findings"]
                ))
            if expected.get("finding_omitted"):
                checks.append(not any(
                    finding["claim"] == expected["finding_omitted"]
                    for finding in validated["findings"]
                ))
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
            sum(item.get("valid_evidence_references", 0) for item in results)
            / sum(item.get("total_evidence_references", 0) for item in results),
            4,
        ) if sum(item.get("total_evidence_references", 0) for item in results) else None,
        "unsupported_claim_rate": round(
            sum(item.get("unsupported_finding_count", 0) for item in results)
            / sum(item.get("input_finding_count", 0) for item in results),
            4,
        ) if sum(item.get("input_finding_count", 0) for item in results) else 0.0,
        "validator_quality_metrics": {
            "input_findings": sum(item.get("input_finding_count", 0) for item in results),
            "retained_findings": sum(item.get("retained_finding_count", 0) for item in results),
            "omitted_findings": sum(item.get("omitted_finding_count", 0) for item in results),
            "unsupported_findings": sum(item.get("unsupported_finding_count", 0) for item in results),
            "downgraded_findings": sum(item.get("downgraded_finding_count", 0) for item in results),
            "evidence_references": sum(item.get("total_evidence_references", 0) for item in results),
            "valid_evidence_references": sum(item.get("valid_evidence_references", 0) for item in results),
        },
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
    ][:max(1, min(int(max_cases), 30))]
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
                "review_criteria": case.get("review_criteria", []),
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
                "review_criteria": case.get("review_criteria", []),
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
