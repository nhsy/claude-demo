"""report: the rule catalogue parsed from rules.md, and the Markdown report built from result files."""

import json
from datetime import timedelta

import pytest
import vault_posture as vp
from conftest import NOW


@pytest.fixture(scope="module")
def catalogue():
    return vp.load_catalogue()


def as_dict(f):
    return json.loads(json.dumps(f.to_dict()))


# --------------------------------------------------------------------------- catalogue


def test_every_rule_has_parsed_remediation(catalogue):
    assert catalogue.warning is None
    assert set(catalogue.entries) == set(vp.RULES)
    for rule_id, entry in catalogue.entries.items():
        assert entry.meaning and entry.remediation, rule_id
        assert catalogue.commands(rule_id) or "No catalogue command" in entry.remediation or "VP-" in entry.remediation, rule_id


def test_ranking_covers_every_rule_and_expands_shorthand(catalogue):
    assert set(catalogue.ranking) == set(vp.RULES)
    assert catalogue.ranking[0] == "VP-SEC-001"
    # "VP-AWS-001/002" ranks both, in order
    assert catalogue.ranking.index("VP-AWS-002") == catalogue.ranking.index("VP-AWS-001") + 1
    assert catalogue.rank("VP-SEC-001") < catalogue.rank("VP-PLUG-002")


def test_escaped_pipes_stay_inside_their_cell(catalogue):
    assert "<rate=…|max_leases=…>" in catalogue.commands("VP-QUOTA-003")[0]


def test_referenced_rule_lends_its_commands(catalogue):
    assert catalogue.commands("VP-PKI-002") == catalogue.commands("VP-PKI-001")
    assert catalogue.commands("VP-PKI-007") == catalogue.commands("VP-PKI-001")
    assert catalogue.guidance("VP-PKI-002").startswith("As VP-PKI-001")


def test_no_catalogue_command(catalogue):
    assert catalogue.commands("VP-PLUG-002") == []
    assert "No catalogue command" in catalogue.guidance("VP-PLUG-002")


def test_guidance_only_when_the_cell_says_more_than_its_commands(catalogue):
    assert catalogue.guidance("VP-ROLE-004") is None  # just the command
    assert "If nobody" in catalogue.guidance("VP-SEC-001")


@pytest.mark.parametrize(
    ("text", "warning"),
    [(None, "could not be read"), ("# rules\n\nno table here\n", "has no rule rows")],
)
def test_unreadable_catalogue_warns_and_is_empty(tmp_path, text, warning):
    path = tmp_path / "rules.md"
    if text is not None:
        path.write_text(text)
    catalogue = vp.load_catalogue(path)
    assert warning in catalogue.warning and not catalogue.entries
    assert catalogue.commands("VP-SEC-001") == [] and catalogue.guidance("VP-SEC-001") is None
    assert catalogue.rank("VP-SEC-001") < catalogue.rank("VP-PLUG-002")  # severity still orders unranked rules


# --------------------------------------------------------------------------- filling placeholders


def test_fill_role_path(catalogue):
    f = as_dict(vp.finding("VP-ROLE-004", "jwt_role", "auth/jwt/role/sso", "logs", mount="jwt/", role="sso"))
    assert [vp.fill_command(c, f) for c in catalogue.commands("VP-ROLE-004")] == ["vault write auth/jwt/role/sso verbose_oidc_logging=false"]


def test_fill_pki_mount_falls_back_to_the_object_path(catalogue):
    f = as_dict(vp.finding("VP-PKI-006", "pki_mount", "pki_off/", "no CRL"))
    assert vp.fill_command(catalogue.commands("VP-PKI-006")[0], f).startswith("vault write pki_off/config/crl disable=false")


def test_fill_issuer_quotes_values_and_keeps_operator_choices(catalogue):
    f = as_dict(vp.finding("VP-PKI-002", "pki_issuer", "pki/issuer/abc", "expiring", mount="pki/", issuer_name="critical", common_name="posture critical CA"))
    rotate = vp.fill_command(catalogue.commands("VP-PKI-002")[0], f)
    assert rotate == "vault write pki/root/rotate/internal common_name='posture critical CA' issuer_name=<new>"


def test_fill_cluster_level_rule(catalogue):
    f = as_dict(vp.finding("VP-QUOTA-003", "quota_type", "rate-limit", "scoped", quota_type="rate-limit", paths=["auth/userpass/"]))
    assert vp.fill_command(catalogue.commands("VP-QUOTA-003")[0], f).startswith("vault write sys/quotas/rate-limit/global ")


def test_fill_plugin_name_and_type(catalogue):
    f = as_dict(vp.finding("VP-PLUG-001", "plugin", "secret/custom", "unversioned", plugin_name="custom", plugin_type="secret"))
    assert vp.fill_command(catalogue.commands("VP-PLUG-001")[0], f) == "vault plugin register -sha256=<sha> -version=<semver> secret custom"


def test_namespace_flag_outside_root(catalogue):
    f = as_dict(vp.finding("VP-ROLE-004", "jwt_role", "auth/jwt/role/sso", "logs", namespace="team-a/apps", mount="jwt/"))
    assert vp.fill_command(catalogue.commands("VP-ROLE-004")[0], f) == "vault write -namespace=team-a/apps auth/jwt/role/sso verbose_oidc_logging=false"


def test_boolean_and_list_evidence_never_fill(catalogue):
    f = as_dict(vp.finding("VP-QUOTA-003", "quota_type", "rate-limit", "scoped", quota_type=["rate-limit"]))
    assert "<quota_type>" in vp.fill_command(catalogue.commands("VP-QUOTA-003")[0], f)


# --------------------------------------------------------------------------- report

ROOT = vp.finding("VP-ROLE-001", "token_role", "auth/token/roles/ops-root", "root", mount="token/", role="ops-root")
SSO = vp.finding("VP-ROLE-004", "jwt_role", "auth/jwt/role/sso", "logs claims", mount="jwt/", role="sso")
GEN_ROOT = vp.finding("VP-SEC-001", "seal_operation", "sys/generate-root/attempt", "in progress", operation="root token generation", progress=0, required=1)
PLUGINS = vp.finding("VP-PLUG-002", "plugin_catalog", "sys/plugins/catalog", "1 external plugin", count=1, plugins=["secret/x"])

ROLES_DATA = {
    "namespaces": ["/"],
    "roles": [
        {"namespace": "/", "mount": "jwt/", "type": "jwt", "name": "sso", "config": {}},
        {"namespace": "/", "mount": "jwt/", "type": "jwt", "name": "pinned", "config": {}},
        {"namespace": "/", "mount": "token/", "type": "token", "name": "ops-root", "config": {}},
    ],
}
PKI_DATA = {
    "namespaces": ["/"],
    "mounts": [
        {"namespace": "/", "mount": "pki/", "auto_tidy": {"enabled": True}, "crl": {"disable": True, "ocsp_disable": False}, "urls": {}},
        {"namespace": "/", "mount": "old/", "auto_tidy": None, "crl": None, "urls": None},
    ],
    "issuers": [
        {"namespace": "/", "mount": "pki/", "issuer_id": "abcdef1234", "config": {"issuer_name": "root-2026"}, "certificate": {"not_after": "2026-11-01T00:00:00Z"}},
        {"namespace": "/", "mount": "pki/", "issuer_id": "0123456789", "config": {}, "certificate": None},
    ],
}
QUOTA_DATA = {"config": {}, "rate_limit": [{"name": "login", "path": "auth/userpass/"}], "lease_count": [{"name": "default", "path": "", "max_leases": 300000}]}
SECURITY_DATA = {"external_plugins": [{"name": "x"}], "key_status": {"term": 2, "install_time": "2026-01-01T00:00:00.123456789Z"}}


def document(findings, *, at=NOW, cluster="vault-a", scopes=(("mounts", vp.OK, ""),), data=None, addr="https://vault.example:8200"):
    coverage = vp.Coverage()
    for scope, status, namespace in scopes:
        coverage.record(scope, status, "connection reset" if status == vp.ERROR else None, namespace)
    run = vp.run_block({"cluster_name": cluster, "version": "2.1.1+ent"}, addr, at)
    return json.loads(json.dumps(vp.build_document(run, coverage, findings, data or {})))


def render(documents, diff=None, catalogue=None):
    return vp.render_report(vp.merge_documents(documents), catalogue or vp.load_catalogue(), diff, ["a.json"])


def write(path, doc):
    path.write_text(json.dumps(doc))
    return str(path)


def headings(text, level="## "):
    return [line[len(level) :] for line in text.splitlines() if line.startswith(level)]


def prose_lines(text):
    """Lines outside tables and fenced code: the ones vault-tools' markdownlint limits to 300 characters."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and not line.startswith("|"):
            out.append(line)
    return out


def test_report_cli_offline(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("report must not make HTTP requests")

    monkeypatch.setattr(vp.requests.Session, "request", no_network)
    source = write(tmp_path / "posture.json", document([ROOT, SSO]))
    out_dir = tmp_path / "out"
    assert vp.main(["report", source, "--output-dir", str(out_dir)]) == vp.EXIT_OK
    out = vp.Path(capsys.readouterr().out.strip())
    assert out.parent == out_dir and out.name.startswith("vault-a-report-") and out.suffix == ".md"
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert (out_dir / ".gitignore").exists()
    assert out.read_text().startswith("# Vault posture report: `vault-a`")


def test_report_rejects_other_files(tmp_path, capsys):
    good = write(tmp_path / "ok.json", document([]))
    access = write(tmp_path / "access.json", {"run": {"mode": "offline"}, "policies": {}, "queries": []})
    (tmp_path / "notes.txt").write_text("not json")
    cases = [
        ([access], "not a vault-posture findings document"),
        ([str(tmp_path / "notes.txt")], "not a JSON file"),
        ([str(tmp_path / "missing.json")], "file not found"),
        ([good, "--diff", good], "not a vault-posture diff document"),
        ([good, "--diff", str(tmp_path / "notes.txt")], "not a JSON file"),
        ([good, "--diff", str(tmp_path / "gone.json")], "file not found"),
    ]
    for argv, message in cases:
        assert vp.main(["report", *argv, "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
        assert message in capsys.readouterr().err
    assert not list(tmp_path.glob("*-report-*.md"))


def test_report_rejects_mixed_clusters(tmp_path, capsys):
    a = write(tmp_path / "a.json", document([ROOT]))
    b = write(tmp_path / "b.json", document([SSO], cluster="vault-b"))
    assert vp.main(["report", a, b, "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    assert "different clusters (vault-a, vault-b)" in capsys.readouterr().err
    other = vp.diff_documents(document([], cluster="vault-b"), document([], cluster="vault-b"), NOW)
    d = write(tmp_path / "diff.json", other)
    assert vp.main(["report", a, "--diff", d, "--output-dir", str(tmp_path)]) == vp.EXIT_FATAL
    assert "the diff describes cluster vault-b" in capsys.readouterr().err
    assert not list(tmp_path.glob("*-report-*.md"))


def test_missing_catalogue_falls_back_to_titles(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(vp, "CATALOGUE_PATH", tmp_path / "gone.md")
    source = write(tmp_path / "posture.json", document([ROOT]))
    assert vp.main(["report", source, "--output-dir", str(tmp_path)]) == vp.EXIT_OK
    captured = capsys.readouterr()
    assert "warning: rule catalogue gone.md could not be read" in captured.err
    text = vp.Path(captured.out.strip()).read_text()
    assert "### 1. Role can issue tokens with the root policy (VP-ROLE-001, high)" in text
    assert "For an operator to run" not in text and "**Remediation:** rule catalogue gone.md could not be read" in text


def test_sections_in_order_with_every_part():
    diff = vp.diff_documents(document([SSO], at=NOW - timedelta(days=1)), document([ROOT, SSO]), NOW)
    data = {"roles": ROLES_DATA, "pki": PKI_DATA, "quotas": QUOTA_DATA, "security": SECURITY_DATA}
    text = render([document([ROOT, SSO], data=data)], diff=diff)
    assert headings(text) == ["Executive summary", "Summary metrics", "Inventory", "Findings, ranked", "Summary", "Changes since the last run", "Not covered", "Source files"]
    assert text.startswith("# Vault posture report: `vault-a`\n\n|  |  |\n| --- | --- |\n| Cluster | `vault-a` |")


def test_header_counts_and_run():
    early = document([ROOT], at=NOW, addr="<redacted>")
    late = document([SSO], at=NOW + timedelta(hours=1))
    text = render([late, early])
    assert "| Findings | **2**: 1 high, 1 low |" in text
    assert "| Address | `<redacted>` |" in text  # any redacted input redacts the report
    assert "| Run time | 2026-10-05 00:00–01:00 UTC |" in text
    assert "| Vault version | 2.1.1+ent (Enterprise) |" in text


def test_run_time_formats():
    assert vp._when(None, None) == "unknown"
    assert vp._when("2026-10-05T00:00:00Z", "2026-10-05T00:00:00Z") == "2026-10-05 00:00 UTC"
    assert vp._when("2026-10-05T23:00:00Z", "2026-10-06T01:00:00Z") == "2026-10-05 23:00 – 2026-10-06 01:00 UTC"


def test_duplicate_findings_render_once():
    posture = document([ROOT, SSO])
    roles = document([ROOT], at=NOW + timedelta(minutes=5))
    text = render([posture, roles])
    assert text.count("`auth/token/roles/ops-root`: root") == 1
    assert "| Findings | **2**: 1 high, 1 low |" in text


def test_groups_follow_catalogue_ranking():
    text = render([document([PLUGINS, SSO, ROOT, GEN_ROOT])])
    assert [vp.RULE_REFERENCE.findall(h)[0] for h in headings(text, "### ")] == ["VP-SEC-001", "VP-ROLE-001", "VP-ROLE-004", "VP-PLUG-002"]


def test_group_heading_counts_and_examples():
    roles = [vp.finding("VP-ROLE-004", "jwt_role", f"auth/jwt/role/r{i}", f"role {i}", mount="jwt/") for i in range(5)]
    text = render([document(roles)])
    assert "### 1. OIDC role logs tokens and claims verbosely (VP-ROLE-004, low, ×5)" in text
    assert "- `/` `auth/jwt/role/r2`: role 2" in text and "auth/jwt/role/r3`: role 3" not in text
    assert "- …and 2 more in the result files." in text
    assert "# …and 2 more, one per finding" in text
    assert text.count("verbose_oidc_logging=false\n") == 3


def test_single_finding_shows_detail_and_commands():
    text = render([document([SSO])])
    assert "`/` `auth/jwt/role/sso`: logs claims" in text
    assert "For an operator to run:\n\n```bash\nvault write auth/jwt/role/sso verbose_oidc_logging=false\n```" in text
    assert "**Watch out:** Meant for short debugging sessions only" in text
    assert "**Remediation:**" not in text  # the cell is only the command


def test_no_catalogue_command_and_guidance():
    text = render([document([PLUGINS, GEN_ROOT])])
    assert "For an operator (no catalogue command): review each plugin" in text
    assert "**Remediation:** If nobody on the operator team started it" in text
    assert "**A root or recovery token generation is in progress** (VP-SEC-001)" in text


def test_namespaced_finding_gets_the_flag():
    f = vp.finding("VP-ROLE-004", "jwt_role", "auth/jwt/role/sso", "logs", namespace="team-a", mount="jwt/")
    assert "vault write -namespace=team-a auth/jwt/role/sso verbose_oidc_logging=false" in render([document([f])])


def test_incomplete_coverage_opens_summary():
    scopes = (("roles.jwt/", vp.DENIED, "team-a"), ("pki.pki/issuers", vp.ERROR, ""), ("mounts", vp.OK, ""))
    text = render([document([SSO], scopes=scopes)])
    summary = text.split("## Executive summary\n\n")[1]
    assert summary.startswith("**Coverage is incomplete** (1 denied read, 1 error), so every conclusion below is partial.")
    assert "| Coverage | **Partial**: 1 denied read, 1 error |" in text
    assert "**Denied reads:** `roles.jwt/` (`team-a/`)" in text
    assert "**Error:** `pki.pki/issuers` (`/`): connection reset." in text


def test_unsupported_and_not_applicable_are_not_covered_not_findings():
    scopes = (("quotas.lease_count", vp.UNSUPPORTED, ""), ("security.rekey_recovery", vp.NOT_APPLICABLE, ""), ("namespaces", vp.ABSENT, ""))
    text = render([document([], scopes=scopes)])
    assert "Coverage is complete" in text
    assert "**Not available on this edition:** `quotas.lease_count` (`/`)." in text
    assert "**Not applicable here:** `security.rekey_recovery` (`/`)." in text
    assert "namespaces" not in text.split("## Not covered")[1]  # absent means none defined, not a gap


def test_no_findings():
    text = render([document([])])
    assert text.count("_No findings._") == 2 and "| Rule |" not in text
    assert "No findings were raised." in text and "| Findings | **0** |" in text


def test_cells_escape_pipes_and_newlines():
    assert vp.md_table(["a"], [["x|y\nz"]]) == "| a |\n| --- |\n| x\\|y z |"
    assert vp.md_escape("a\\|b") == "a\\\\\\|b"  # an escaped backslash, then an escaped pipe: still one cell
    assert vp.md_table(["a"], []) == "_No entries._"
    text = render([document([vp.finding("VP-ROLE-004", "jwt_role", "auth/jwt/role/a|b", "line one\nline two", mount="jwt/")])])
    assert "line one line two" in text


def test_summary_metrics_and_inventory():
    data = {"roles": ROLES_DATA, "pki": PKI_DATA, "quotas": QUOTA_DATA, "security": SECURITY_DATA}
    text = render([document([ROOT, SSO], data=data)])
    assert "| Namespaces | 1 (`/`) |" in text
    assert "| Auth roles reviewed | 3 on 2 mounts, 2 with findings |" in text
    assert "| PKI mounts / issuers | 2 / 2 |" in text
    assert "| Rate-limit quotas | 1 (scoped to `auth/userpass/`) |" in text
    assert "| Lease-count quotas | 1 (1 built-in `default`, untouched) |" in text
    assert "| External plugins | 1 |" in text and "| Barrier key | term 2, installed 2026-01-01 |" in text
    assert "| `/` | `jwt/` | jwt | 2 | 1 |" in text and "| `/` | `token/` | token | 1 | 1 |" in text
    assert "Roles with no findings: `jwt/pinned`." in text
    assert "| `/` | `pki/` | `root-2026` (expires 2026-11-01), `01234567` | on | OCSP only |" in text
    assert "| `/` | `old/` | none | unknown | unknown |" in text


def test_metrics_and_inventory_skip_what_was_not_collected():
    text = render([document([SSO])])
    assert "## Summary metrics" not in text and "## Inventory" not in text


def test_many_namespaces_and_clean_roles_are_capped():
    namespaces = [f"ns{i}/" for i in range(7)]
    roles = [{"namespace": "/", "mount": "jwt/", "type": "jwt", "name": f"r{i}", "config": {}} for i in range(12)]
    text = render([document([], data={"roles": {"namespaces": namespaces, "roles": roles}})])
    assert "| Namespaces | 7 (`ns0/`, `ns1/`, `ns2/`, `ns3/`, `ns4/`, …) |" in text
    assert "and 2 more." in text


def test_diff_section():
    issuer = vp.finding("VP-PKI-002", "pki_issuer", "pki/issuer/aaaa", "expiring", mount="pki/", issuer_name="root", common_name="CA")
    reissued = vp.finding("VP-PKI-002", "pki_issuer", "pki/issuer/bbbb", "expiring", mount="pki/", issuer_name="root", common_name="CA")
    old = document([SSO, issuer], at=NOW - timedelta(days=1))
    new = document([ROOT, reissued], scopes=(("mounts", vp.DENIED, ""),))
    diff = vp.diff_documents(old, new, NOW)
    text = render([new], diff=diff)
    changes = text.split("## Changes since the last run\n\n")[1].split("\n## ")[0]
    assert changes.startswith("Compared with the run of 2026-10-04 00:00 UTC: **1 new**, **1 resolved**, 0 unchanged, 1 rotated.")
    assert "- **Warning:** the new run's coverage is incomplete" in changes
    assert "- New: VP-ROLE-001 `/` `auth/token/roles/ops-root`: root" in changes
    assert "- Resolved: VP-ROLE-004 `/` `auth/jwt/role/sso`: logs claims" in changes
    assert "- Rotated: 1 PKI finding moved to a re-issued CA of the same name; still open, not fixed." in changes


@pytest.mark.parametrize("fixture", sorted((vp.Path(__file__).resolve().parents[1] / "evals").glob("**/fixtures/**/*-posture-*.json")))
def test_lines_within_300_chars(fixture):
    text = render([json.loads(fixture.read_text())])
    assert "## Findings, ranked" in text
    assert max(len(line) for line in prose_lines(text)) <= 300
