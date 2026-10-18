"""Side-by-side summary of `task eval:judge`: one `claude plugin eval --json` file per agent model.

Usage: eval_judge_report.py <dir>   (reads <dir>/<model>.json, writes <dir>/summary.md and prints it)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MODELS = ("opus", "sonnet", "haiku")


def load(results_dir: Path) -> dict[str, dict]:
    """Model name -> parsed eval result, for the models that have a result file."""
    out = {}
    for model in MODELS:
        path = results_dir / f"{model}.json"
        if path.is_file():
            out[model] = json.loads(path.read_text())
    return out


def runs(case: dict) -> list[dict]:
    return case.get("arms", {}).get("with", [])


def score(case: dict) -> float:
    return case.get("aggregates", {}).get("score", 0.0)


def passed(case: dict) -> bool:
    return bool(runs(case)) and all(r.get("passed") for r in runs(case))


def case_cell(case: dict) -> str:
    """'✓ 1.00' when every run passed, else '✗ <score>' and the failing grader names."""
    score_ = score(case)
    if passed(case):
        return f"✓ {score_:.2f}"
    failed = sorted({g["name"] for r in runs(case) for g in r.get("graders", []) if not g.get("passed")})
    errors = [r["error"] for r in runs(case) if r.get("error")]
    why = ", ".join(failed) or ("error" if errors else "")
    return f"✗ {score_:.2f}" + (f" ({why})" if why else "")


def render(results: dict[str, dict]) -> str:
    if not results:
        return "No eval:judge results found.\n"
    models = list(results)
    by_model = {m: {c["name"]: c for c in r.get("cases", [])} for m, r in results.items()}
    names = sorted({n for cases in by_model.values() for n in cases})

    lines = [
        "| Case | " + " | ".join(models) + " |",
        "| --- |" + " --- |" * len(models),
    ]
    for name in names:
        cells = [case_cell(by_model[m][name]) if name in by_model[m] else "-" for m in models]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")

    n_passed, mean, cost = [], [], []
    for m in models:
        cases = list(by_model[m].values())
        ok = sum(1 for c in cases if passed(c))
        n_passed.append(f"**{ok}/{len(cases)}**")
        mean.append(f"{sum(score(c) for c in cases) / len(cases):.2f}" if cases else "-")
        cost.append(f"${results[m].get('costUsd', 0.0):.2f}")
    lines += [
        "| Cases passed | " + " | ".join(n_passed) + " |",
        "| Mean score | " + " | ".join(mean) + " |",
        "| Cost | " + " | ".join(cost) + " |",
    ]
    missing = [m for m in MODELS if m not in results]
    if missing:
        lines += ["", "No results for: " + ", ".join(missing) + "."]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    results_dir = Path(argv[0])
    summary = render(load(results_dir))
    if results_dir.is_dir():
        (results_dir / "summary.md").write_text(summary)
    print(summary, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
