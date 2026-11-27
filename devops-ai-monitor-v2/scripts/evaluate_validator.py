"""Run deterministic evidence-validator fixtures without contacting Ollama."""
import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from ai_investigator import INVESTIGATION_PROMPT_VERSION, IncidentInvestigator
from evaluation import run_evaluation


def main():
    parser = argparse.ArgumentParser(
        description="Run deterministic DevOps AI investigation validator fixtures."
    )
    parser.add_argument("--model", default=os.getenv("OLLAMA_MODEL", "qwen2.5:3b"))
    parser.add_argument("--run-name", default="deterministic-evidence-regression")
    parser.add_argument("--prompt-version", default=INVESTIGATION_PROMPT_VERSION)
    parser.add_argument("--output", default="", help="Optional JSON report path.")
    args = parser.parse_args()

    investigator = IncidentInvestigator(None, "", args.model)
    report = run_evaluation(
        investigator,
        run_name=args.run_name,
        prompt_version=args.prompt_version,
    )
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nReport saved to: {output_path}")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
