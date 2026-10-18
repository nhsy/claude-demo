"""scripts/eval_judge_report.py: the side-by-side model table for `task eval:judge`, and the
eval suite it runs (10 offline cases)."""

import importlib.util
import json

from conftest import ROOT

spec = importlib.util.spec_from_file_location("eval_judge_report", ROOT / "scripts/eval_judge_report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def run(*graders, error=None):
    return {
        "passed": all(ok for _, ok in graders) and error is None,
        "costUsd": 0.1,
        "error": error,
        "graders": [{"name": n, "passed": ok, "explanation": ""} for n, ok in graders],
    }


def result(cost, *cases):
    return {"schemaVersion": 1, "costUsd": cost, "cases": list(cases)}


def case(name, score, *runs):
    return {"name": name, "arms": {"with": list(runs)}, "aggregates": {"score": score, "passRate": score}}


def write(tmp_path, model, data):
    (tmp_path / f"{model}.json").write_text(json.dumps(data))


def test_table_compares_models_per_case(tmp_path):
    write(
        tmp_path,
        "opus",
        result(1.5, case("refuse-write", 1.0, run(("skill-fired", True), ("observe-only", True)))),
    )
    write(
        tmp_path,
        "haiku",
        result(0.25, case("refuse-write", 0.5, run(("skill-fired", True), ("observe-only", False)))),
    )

    out = report.main([str(tmp_path)])
    summary = (tmp_path / "summary.md").read_text()

    assert out == 0
    assert "| Case | opus | haiku |" in summary
    assert "| refuse-write | ✓ 1.00 | ✗ 0.50 (observe-only) |" in summary
    assert "| Cases passed | **1/1** | **0/1** |" in summary
    assert "| Cost | $1.50 | $0.25 |" in summary
    assert "No results for: sonnet." in summary


def test_case_missing_for_a_model_and_run_errors(tmp_path):
    write(tmp_path, "opus", result(0, case("a", 1.0, run(("g", True))), case("b", 0.0, run(error="timeout"))))
    write(tmp_path, "sonnet", result(0, case("a", 1.0, run(("g", True)))))

    summary = report.render(report.load(tmp_path))

    assert "| b | ✗ 0.00 (error) | - |" in summary
    assert "| Cases passed | **1/2** | **1/1** |" in summary


def test_no_results(tmp_path):
    assert report.render(report.load(tmp_path)) == "No eval:judge results found.\n"


def test_suite_has_ten_offline_cases():
    prompts = sorted((ROOT / "evals").glob("*/prompt.md"))
    assert len(prompts) == 10
    for prompt in prompts:
        front = prompt.read_text().split("---")[1]
        assert "offline" in front, prompt
        assert list((prompt.parent / "graders").glob("*.md")), prompt
