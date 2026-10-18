"""Offline ACL evaluation (`access`): HCL/JSON parsing and Vault's path matching rules.

EXPECTED was produced by Vault 2.1.1 itself (sys/capabilities for a token holding the three
fixture policies); tests/test_integration.py re-checks it against a live server.
"""

import json
from pathlib import Path

import jsonschema
import pytest
import vault_posture as vp
from conftest import FIXTURE_POLICIES

EXPECTED = {
    "secret/data/app/x": ["list", "read", "update"],  # same glob in two policies: merged
    "secret/data/app/admin/key": ["deny"],  # longer glob wins, deny beats everything
    "secret/data/team/x": ["create", "read", "update"],  # `+` segment
    "secret/data/exact": ["read"],  # exact path beats the `+/*` glob
    "secret/data/exact2": ["deny"],  # `+/*` needs one more segment
    "secret/metadata/app/config": ["read"],
    "secret/metadata/app/other": ["deny"],  # no rule: implicit deny
    "sys/policies/acl/foo": ["list", "read"],  # nested allowed_parameters block is skipped
    "kv/legacy/a": ["create", "delete", "list", "read", "update"],  # legacy policy = "write"
    "kv/legacy/locked": ["create", "delete", "list", "read", "update"],  # later first wildcard wins over kv/+/locked
    "kv/other/locked": ["deny"],
    "nothing/here": ["deny"],
}


@pytest.fixture(scope="module")
def fixture_rules():
    rules, loaded, unparsed = vp.load_policies([str(FIXTURE_POLICIES)])
    assert sorted(loaded) == ["app", "legacy", "ops"] and unparsed == []
    return rules


@pytest.mark.parametrize(("path", "capabilities"), sorted(EXPECTED.items()))
def test_matches_vault(fixture_rules, path, capabilities):
    assert vp.effective_capabilities(fixture_rules, path)["capabilities"] == capabilities


def test_decisions(fixture_rules):
    assert vp.effective_capabilities(fixture_rules, "secret/data/app/admin/key")["decision"] == "explicit_deny"
    assert vp.effective_capabilities(fixture_rules, "nothing/here") == {"capabilities": ["deny"], "decision": "implicit_deny", "matched_path": None, "policies": []}
    merged = vp.effective_capabilities(fixture_rules, "secret/data/app/x")
    assert merged["matched_path"] == "secret/data/app/*" and merged["policies"] == ["app", "ops"]


def test_parse_hcl_comments_heredoc_and_nested_blocks():
    text = """
    # comment with path "fake" { capabilities = ["sudo"] }
    path "a/*" {   // trailing comment
      capabilities = ["read", "list"]
      required_parameters = ["x"]
      allowed_parameters = { "y" = ["1", "2"], "z" = [] }
    }
    /* block
       comment */
    path "b" { capabilities = ["deny"] }
    path "c#not-a-comment" { capabilities = ["update"] }
    """
    rules = vp.parse_policy("p", text)
    assert [(r.path, r.capabilities) for r in rules] == [("a/*", ("read", "list")), ("b", ("deny",)), ("c#not-a-comment", ("update",))]


def test_parse_json_policy():
    rules = vp.parse_policy("j", json.dumps({"path": {"x/*": {"capabilities": ["read"]}, "y": {"policy": "sudo"}}}))
    assert {r.path: r.capabilities for r in rules} == {"x/*": ("read",), "y": ("create", "read", "update", "delete", "list", "sudo")}


def test_unparseable_files_are_reported_not_fatal(tmp_path):
    (tmp_path / "good.hcl").write_text('path "a" { capabilities = ["read"] }')
    (tmp_path / "bad.json").write_text("{ not json")
    (tmp_path / "notes.txt").write_text("ignored")
    rules, loaded, unparsed = vp.load_policies([str(tmp_path)])
    assert loaded == ["good"] and len(rules) == 1
    assert unparsed == [{"file": str(tmp_path / "bad.json"), "reason": "ValueError"}]


@pytest.mark.parametrize(
    ("glob", "path", "matches"),
    [
        ("secret/+/x", "secret/a/x", True),
        ("secret/+/x", "secret/a/b/x", False),
        ("secret/+", "secret/", False),
        ("secret/*", "secret/", True),
        ("secret/a*", "secret/abc/def", True),
        ("+/sys/auth", "team-a/sys/auth", True),
        ("a.b/*", "aXb/c", False),  # dots are literal
    ],
)
def test_glob_regex(glob, path, matches):
    assert bool(vp.glob_regex(glob).match(path)) is matches


def test_access_cli_offline(tmp_path, monkeypatch, access_schema, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    code = vp.main(["access", "--policy", str(FIXTURE_POLICIES), "--path", "secret/data/app/x", "--path", "nothing/here", "--capability", "update", "--output-dir", str(tmp_path)])
    assert code == vp.EXIT_OK
    out = capsys.readouterr().out.strip()
    document = json.loads(Path(out).read_text())
    jsonschema.validate(document, access_schema)
    first = document["queries"][0]
    # Alone, app.hcl gives read/list here: only ops.hcl grants update.
    assert first["granted_by"] == ["ops"] and first["combined_allows"] is True
    assert [p["policy"] for p in first["per_policy"]] == ["app", "ops"]
    assert document["queries"][1]["combined"]["decision"] == "implicit_deny"
    assert document["queries"][1]["per_policy"] == []


def test_access_cli_errors(tmp_path, capsys):
    assert vp.main(["access", "--policy", str(tmp_path / "missing"), "--path", "x", "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    assert "policy source not found" in capsys.readouterr().err
    (tmp_path / "empty.hcl").write_text("# nothing\n")
    assert vp.main(["access", "--policy", str(tmp_path / "empty.hcl"), "--path", "x", "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    assert "no ACL path rules" in capsys.readouterr().err
