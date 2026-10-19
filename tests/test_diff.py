"""diff: comparing two findings documents by fingerprint, offline."""

import json
from datetime import timedelta
from pathlib import Path

import jsonschema
import pytest
import vault_posture as vp
from conftest import NOW

ROOT_ROLE = vp.finding("VP-ROLE-001", "token_role", "auth/token/roles/ops-root", "root")
AUDIENCE = vp.finding("VP-ROLE-002", "jwt_role", "auth/jwt/role/ci", "aud only")
K8S = vp.finding("VP-ROLE-005", "kubernetes_role", "auth/kubernetes/role/any-pod", "any pod", namespace="team-a")


def issuer(rule_id, issuer_id, name, mount="pki/"):
    return vp.finding(rule_id, "pki_issuer", f"{mount}issuer/{issuer_id}", "expiring", mount=mount, issuer_name=name, common_name="CA")


def document(findings, *, at=NOW, cluster="vault-a", namespace="", edition="community", complete=True):
    coverage = vp.Coverage()
    coverage.record("mounts", vp.OK if complete else "denied")
    run = vp.run_block({"cluster_name": cluster, "version": "2.1.1+ent" if edition == "enterprise" else "2.1.1"}, "<redacted>", at, namespace)
    return json.loads(json.dumps(vp.build_document(run, coverage, findings, {})))


def fingerprints(findings):
    return {f["fingerprint"] for f in findings}


def test_new_resolved_unchanged():
    old = document([ROOT_ROLE, AUDIENCE])
    new = document([AUDIENCE, K8S], at=NOW + timedelta(days=7))
    diff = vp.diff_documents(old, new, NOW)
    assert fingerprints(diff["findings"]["new"]) == {K8S.fingerprint}
    assert fingerprints(diff["findings"]["resolved"]) == {ROOT_ROLE.fingerprint}
    assert fingerprints(diff["findings"]["unchanged"]) == {AUDIENCE.fingerprint}
    assert diff["summary"]["new"] == {"total": 1, "by_severity": {"high": 1, "medium": 0, "low": 0, "info": 0}, "by_rule": {"VP-ROLE-005": 1}}
    assert diff["summary"]["resolved"]["by_rule"] == {"VP-ROLE-001": 1}
    assert diff["summary"]["unchanged"] == 1
    assert diff["warnings"] == []
    assert diff["runs"] == {"old": old["run"], "new": new["run"]}


def test_identical_runs_have_nothing_new_or_resolved():
    old = document([ROOT_ROLE, AUDIENCE])
    diff = vp.diff_documents(old, document([AUDIENCE, ROOT_ROLE], at=NOW + timedelta(hours=1)), NOW)
    assert diff["summary"]["new"]["total"] == diff["summary"]["resolved"]["total"] == 0
    assert diff["summary"]["unchanged"] == 2


def test_rotated_issuer_is_paired_by_name_not_reported_as_resolved_and_new():
    old = document([issuer("VP-PKI-002", "aaaa", "root-2025"), issuer("VP-PKI-005", "cccc", None)])
    new = document([issuer("VP-PKI-002", "bbbb", "root-2025"), issuer("VP-PKI-005", "dddd", None)], at=NOW + timedelta(days=1))
    diff = vp.diff_documents(old, new, NOW)
    [pair] = diff["findings"]["rotated"]
    assert pair["old"]["object"]["path"] == "pki/issuer/aaaa"
    assert pair["new"]["object"]["path"] == "pki/issuer/bbbb"
    assert diff["summary"]["rotated"] == 1
    # Unnamed issuers can't be paired: they stay resolved + new.
    assert [f["object"]["path"] for f in diff["findings"]["resolved"]] == ["pki/issuer/cccc"]
    assert [f["object"]["path"] for f in diff["findings"]["new"]] == ["pki/issuer/dddd"]


def test_issuer_pairing_needs_the_same_rule_and_mount():
    old = document([issuer("VP-PKI-002", "aaaa", "root"), issuer("VP-PKI-003", "eeee", "int", mount="pki_a/")])
    new = document([issuer("VP-PKI-003", "bbbb", "root"), issuer("VP-PKI-003", "ffff", "int", mount="pki_b/")], at=NOW + timedelta(days=1))
    diff = vp.diff_documents(old, new, NOW)
    assert diff["findings"]["rotated"] == []
    assert diff["summary"]["resolved"]["total"] == diff["summary"]["new"]["total"] == 2


@pytest.mark.parametrize(
    ("changes", "field"),
    [({"cluster": "vault-b"}, "cluster_name"), ({"namespace": "team-a"}, "start_namespace"), ({"edition": "enterprise"}, "edition")],
)
def test_mismatched_runs_warn(changes, field):
    diff = vp.diff_documents(document([ROOT_ROLE]), document([ROOT_ROLE], at=NOW + timedelta(days=1), **changes), NOW)
    assert len(diff["warnings"]) == 1
    assert field in diff["warnings"][0]


@pytest.mark.parametrize("which", ["old", "new"])
def test_incomplete_coverage_warns(which):
    old = document([ROOT_ROLE], complete=which != "old")
    new = document([], at=NOW + timedelta(days=1), complete=which != "new")
    diff = vp.diff_documents(old, new, NOW)
    [warning] = diff["warnings"]
    assert f"the {which} run's coverage is incomplete" in warning


def test_reversed_order_warns():
    diff = vp.diff_documents(document([ROOT_ROLE], at=NOW + timedelta(days=7)), document([], at=NOW), NOW)
    assert diff["warnings"] == ["the new run is older than the old one: the files may be in the wrong order"]


def test_fingerprint_is_stable():
    # Pinned: changing fingerprint inputs would make every finding of an earlier run look new.
    assert ROOT_ROLE.fingerprint == "f71ccca069c0b05b"


def write(path, document):
    path.write_text(json.dumps(document))
    return str(path)


def test_diff_cli_offline(tmp_path, monkeypatch, diff_schema, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    old = write(tmp_path / "old.json", document([ROOT_ROLE, issuer("VP-PKI-002", "aaaa", "root")]))
    new = write(tmp_path / "new.json", document([K8S, issuer("VP-PKI-002", "bbbb", "root")], at=NOW + timedelta(days=1), complete=False))
    out_dir = tmp_path / "out"
    assert vp.main(["diff", old, new, "--output-dir", str(out_dir)]) == vp.EXIT_OK
    out = Path(capsys.readouterr().out.strip())
    assert out.parent == out_dir and out.name.startswith("vault-a-diff-")
    document_ = json.loads(out.read_text())
    jsonschema.validate(document_, diff_schema)
    assert document_["summary"]["rotated"] == 1 and document_["warnings"]


def test_diff_cli_rejects_other_files(tmp_path, capsys):
    findings = write(tmp_path / "ok.json", document([]))
    access = write(tmp_path / "access.json", {"run": {"mode": "offline"}, "policies": {}, "queries": []})
    (tmp_path / "notes.txt").write_text("not json")
    for bad, message in ((access, "not a vault-posture findings document"), (str(tmp_path / "notes.txt"), "not a JSON file"), (str(tmp_path / "missing.json"), "file not found")):
        assert vp.main(["diff", findings, bad, "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
        assert message in capsys.readouterr().err
    assert not list(tmp_path.glob("*-diff-*.json"))
