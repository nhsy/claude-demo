"""report: the rule catalogue parsed from rules.md, and the Markdown report built from result files."""

import json

import pytest
import vault_posture as vp


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
