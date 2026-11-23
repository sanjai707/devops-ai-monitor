import json
from pathlib import Path

from ai_investigator import IncidentInvestigator, InvestigationError


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
        "root_cause_accuracy": round(passed / len(results), 4) if results else 0.0,
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
