"""CLI wiring: output files, exit codes, setup errors and the document schema."""

import json
import stat

import jsonschema
import pytest
import vault_posture as vp
from conftest import HEALTH, fake_response
from hvac import exceptions as hvac_exc


def run(tmp_path, *argv):
    code = vp.main([*argv, "--output-dir", str(tmp_path)])
    return code, sorted(tmp_path.glob("*.json"))


@pytest.mark.parametrize(("command", "kind"), [("audit", "posture"), ("quotas", "quotas"), ("security", "security"), ("roles", "roles"), ("pki", "pki")])
def test_writes_one_private_file_and_prints_its_path(fake_vault, tmp_path, capsys, command, kind):
    out_dir = tmp_path / "results"
    code, _ = run(out_dir, command)
    files = sorted(out_dir.glob("*.json"))
    assert code == vp.EXIT_OK
    assert len(files) == 1
    assert files[0].name.startswith(f"vault-cluster-test-{kind}-")
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert (out_dir / ".gitignore").read_text().splitlines()[-1] == "*"
    assert capsys.readouterr().out.strip() == str(files[0])


def test_audit_document_matches_schema_and_expected_findings(fake_vault, tmp_path, schema):
    _, files = run(tmp_path, "audit")
    document = json.loads(files[0].read_text())
    jsonschema.validate(document, schema)
    assert document["run"]["edition"] == "community"
    assert document["run"]["vault_addr"] == "http://vault.test:8200"
    assert document["coverage"]["complete"] is True
    assert document["summary"]["by_rule"] == {
        "VP-PKI-002": 1,
        "VP-PKI-004": 1,
        "VP-PLUG-001": 1,
        "VP-PLUG-002": 1,
        "VP-QUOTA-003": 1,
        "VP-QUOTA-004": 1,
        "VP-ROLE-002": 1,
        "VP-ROLE-005": 1,
        "VP-SEC-001": 1,
        "VP-SEC-002": 1,
        "VP-SEC-003": 1,
        "VP-SEC-004": 1,
    }
    # Ranked by severity, high first.
    severities = [f["severity"] for f in document["findings"]]
    assert severities == sorted(severities, key=vp.SEVERITIES.index)
    # Lease-count quotas are Enterprise-only: not judged, and not a coverage gap.
    assert "VP-QUOTA-002" not in document["summary"]["by_rule"]


def test_redact_addr(fake_vault, tmp_path):
    _, files = run(tmp_path, "quotas", "--redact-addr")
    assert json.loads(files[0].read_text())["run"]["vault_addr"] == "<redacted>"


def test_env_output_dir(fake_vault, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VAULT_POSTURE_OUTPUT_DIR", str(tmp_path / "env-dir"))
    assert vp.main(["quotas"]) == vp.EXIT_OK
    assert len(list((tmp_path / "env-dir").glob("*-quotas-*.json"))) == 1


@pytest.mark.parametrize(("fail_on", "expected"), [("high", vp.EXIT_FINDINGS), ("medium", vp.EXIT_FINDINGS)])
def test_fail_on_security(fake_vault, tmp_path, fail_on, expected):
    code, _ = run(tmp_path, "security", "--fail-on", fail_on)
    assert code == expected


def test_fail_on_below_threshold_is_ok(fake_vault, tmp_path):
    # quotas on the fixture yields only low/info findings.
    code, _ = run(tmp_path, "quotas", "--fail-on", "medium")
    assert code == vp.EXIT_OK


def test_fail_on_gaps(fake_vault, tmp_path):
    fake_vault.routes[("sys/key-status", False)] = hvac_exc.Forbidden()
    assert run(tmp_path, "security")[0] == vp.EXIT_OK
    assert run(tmp_path, "security", "--fail-on-gaps")[0] == vp.EXIT_GAPS


def test_missing_env_is_fatal(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    assert vp.main(["audit", "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    assert "VAULT_ADDR and VAULT_TOKEN must be set" in capsys.readouterr().err
    assert not list(tmp_path.glob("*.json"))


def test_rejected_token_is_fatal(fake_vault, tmp_path, capsys):
    fake_vault.routes[("auth/token/lookup-self", False)] = hvac_exc.Forbidden()
    assert run(tmp_path, "audit")[0] == vp.EXIT_FATAL
    assert "token rejected" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("health", "message"),
    [({"sealed": True}, "is sealed"), ({"initialized": False}, "not initialized"), ({"replication_dr_mode": "secondary"}, "DR secondary")],
)
def test_nodes_that_reject_reads_are_fatal(fake_vault, tmp_path, capsys, monkeypatch, health, message):
    original = vp.requests.Session.request

    def request(self, method, url, **kwargs):
        if url.endswith("/v1/sys/health"):
            return fake_response(200, {**HEALTH, **health})
        return original(self, method, url, **kwargs)

    monkeypatch.setattr(vp.requests.Session, "request", request)
    assert run(tmp_path, "audit")[0] == vp.EXIT_FATAL
    assert message in capsys.readouterr().err


def test_unreachable_vault_is_fatal_without_echoing_the_url(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", "x")
    assert vp.main(["audit", "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    err = capsys.readouterr().err
    assert "cannot reach Vault" in err
    assert "ConnectionError" in err


def test_enterprise_edition_detected():
    assert vp.run_block({"version": "2.1.1+ent", "cluster_name": "c"}, "a", vp.utc_now())["edition"] == "enterprise"
