"""Run actual local Ollama investigations against curated evidence fixtures.

Example:
    python scripts/evaluate_ollama.py --model qwen2.5:3b --max-cases 5
"""
import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from ai_investigator import IncidentInvestigator
from evaluation import run_live_model_evaluation


def main():
    parser = argparse.ArgumentParser(description="Evaluate real Ollama responses for human review.")
    parser.add_argument("--url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--model", default=os.getenv("OLLAMA_MODEL", "qwen2.5:3b"))
    parser.add_argument("--max-cases", type=int, default=5)
    parser.add_argument("--case-ids", default="", help="Comma-separated case IDs to run.")
    parser.add_argument("--output", default="", help="Optional JSON report file path.")
    args = parser.parse_args()

    if args.max_cases < 1 or args.max_cases > 12:
        parser.error("--max-cases must be between 1 and 12")

    investigator = IncidentInvestigator(None, args.url, args.model)
    report = run_live_model_evaluation(
        investigator,
        case_ids=[item.strip() for item in args.case_ids.split(",") if item.strip()] or None,
        max_cases=args.max_cases,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)

    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nReport saved to: {output_path}")

    return 0 if report["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
