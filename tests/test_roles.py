"""Auth role checks: each VP-ROLE rule fires on its trigger and stays quiet on its control."""

import pytest
import vault_posture as vp


def role(source, config, name="r", mount=None, namespace=""):
    return vp.AuthRole(namespace, mount or f"{source}/", source, name, config)


def ids(roles):
    return sorted(f.rule_id for f in vp.check_roles(vp.RoleData(roles=roles)))


@pytest.mark.parametrize(
    ("source", "config"),
    [
        ("jwt", {"role_type": "jwt", "bound_subject": "x", "token_policies": ["root"]}),
        ("kubernetes", {"bound_service_account_names": ["a"], "bound_service_account_namespaces": ["b"], "token_policies": ["default", "root"]}),
        ("approle", {"bind_secret_id": True, "secret_id_ttl": 600, "token_policies": ["root"]}),
        ("token", {"allowed_policies": ["root"]}),
        ("token", {"allowed_policies_glob": ["r*"]}),
    ],
)
def test_root_policy_fires_001(source, config):
    assert ids([role(source, config)]) == ["VP-ROLE-001"]


def test_token_role_without_root_is_quiet():
    assert ids([role("token", {"allowed_policies": ["app"], "allowed_policies_glob": ["team-*"], "orphan": True})]) == []


def test_jwt_audience_only_fires_002_and_bindings_quiet_it():
    audience_only = {"role_type": "jwt", "bound_audiences": ["https://github.com/acme"], "bound_subject": "", "bound_claims": None}
    assert ids([role("jwt", audience_only)]) == ["VP-ROLE-002"]
    assert ids([role("jwt", {**audience_only, "bound_subject": "repo:acme/app:ref:refs/heads/main"})]) == []
    assert ids([role("jwt", {**audience_only, "bound_claims": {"repository": "acme/app"}})]) == []
    # OIDC roles authenticate a browser user against redirect URIs: audience-only is normal.
    assert ids([role("jwt", {**audience_only, "role_type": "oidc"})]) == []


def test_wildcard_glob_claims_fire_003():
    config = {"role_type": "jwt", "bound_audiences": ["a"], "bound_claims_type": "glob", "bound_claims": {"repository": ["acme/*", "acme/app"], "ref": "refs/heads/main"}}
    found = vp.check_roles(vp.RoleData(roles=[role("jwt", config)]))
    assert [f.rule_id for f in found] == ["VP-ROLE-003"]
    assert found[0].evidence["wildcard_claims"] == {"repository": ["acme/*"]}


def test_wildcard_in_string_claims_is_literal():
    # bound_claims_type=string compares literally: "*" is not a wildcard there.
    assert ids([role("jwt", {"role_type": "jwt", "bound_claims_type": "string", "bound_claims": {"repository": "acme/*"}})]) == []


def test_verbose_oidc_logging_fires_004():
    assert ids([role("jwt", {"role_type": "oidc", "verbose_oidc_logging": True})]) == ["VP-ROLE-004"]


@pytest.mark.parametrize(
    ("names", "namespaces", "selector", "expected"),
    [
        (["*"], ["*"], "", ["VP-ROLE-005"]),
        (["*"], ["prod"], "", ["VP-ROLE-006"]),
        (["app"], ["*"], "", ["VP-ROLE-006"]),
        (["app"], ["*"], '{"matchLabels":{"team":"a"}}', []),  # the selector narrows "*"
        (["app"], ["prod"], "", []),
    ],
)
def test_kubernetes_wildcards(names, namespaces, selector, expected):
    config = {"bound_service_account_names": names, "bound_service_account_namespaces": namespaces, "bound_service_account_namespace_selector": selector}
    assert ids([role("kubernetes", config)]) == expected


def test_approle_rules():
    assert ids([role("approle", {"bind_secret_id": False, "secret_id_bound_cidrs": ["10.0.0.0/8"]})]) == ["VP-ROLE-007"]
    assert ids([role("approle", {"bind_secret_id": True, "secret_id_ttl": 0})]) == ["VP-ROLE-008"]
    assert ids([role("approle", {"bind_secret_id": True, "secret_id_ttl": 3600})]) == []
    assert ids([role("approle", {"bind_secret_id": True})]) == []  # secret_id_ttl unread: not judged


@pytest.mark.parametrize(
    ("source", "config", "expected"),
    [
        ("approle", {"bind_secret_id": True, "secret_id_ttl": 60, "token_period": 86400}, ["VP-ROLE-009"]),
        ("approle", {"bind_secret_id": True, "secret_id_ttl": 60, "token_period": 86400, "token_explicit_max_ttl": 604800}, []),
        ("token", {"allowed_policies": ["app"], "orphan": True, "token_period": 3600}, ["VP-ROLE-009"]),
        ("token", {"allowed_policies": ["app"], "period": 3600, "explicit_max_ttl": 7200}, []),
        ("kubernetes", {"bound_service_account_names": ["a"], "bound_service_account_namespaces": ["b"], "token_period": "bad"}, []),
    ],
)
def test_periodic_tokens_without_max(source, config, expected):
    assert ids([role(source, config)]) == expected


def test_role_finding_carries_namespace_and_path():
    found = vp.check_roles(vp.RoleData(roles=[role("approle", {"bind_secret_id": False}, name="svc", namespace="team-a")]))
    assert found[0].namespace == "team-a"
    assert found[0].object_path == "auth/approle/role/svc"
    assert found[0].to_dict()["namespace"] == "team-a/"
