from __future__ import annotations

import argparse
import json
from pathlib import Path

from .checker import RepoChecker


def main() -> int:
    parser = argparse.ArgumentParser(prog="repo-steward", description="MIRRORNODE repository checker")
    parser.add_argument("--policy", default="manifests/repo-steward-policy.json")
    parser.add_argument("--output", default="-")
    args = parser.parse_args()

    report = RepoChecker(args.policy).check_all()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output == "-":
        print(rendered)
    else:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 1 if report["overall"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
