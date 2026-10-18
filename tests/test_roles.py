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


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"auth_type": "iam", "bound_iam_principal_arn": ["*"]}, ["VP-AWS-001"]),
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::*:role/*"]}, ["VP-AWS-001"]),
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws-us-gov:iam::12*:role/app"]}, ["VP-AWS-001"]),
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/app-*"]}, []),  # one account, any role name
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/app"], "resolve_aws_unique_ids": True}, []),
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::123456789012:role/app"], "resolve_aws_unique_ids": False}, ["VP-AWS-003"]),
        ({"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::*:role/*"], "resolve_aws_unique_ids": False}, ["VP-AWS-001"]),  # wildcards never resolve
        ({"bound_iam_principal_arn": ["*"]}, ["VP-AWS-001"]),  # auth_type defaults to iam
    ],
)
def test_aws_iam_roles(config, expected):
    assert ids([role("aws", config)]) == expected


def test_aws_wildcard_principal_evidence_shows_account_narrowing():
    plain = {"auth_type": "iam", "bound_iam_principal_arn": ["arn:aws:iam::*:role/*"], "bound_account_id": ["123456789012"]}
    inferred = {**plain, "inferred_entity_type": "ec2_instance"}
    (a,) = vp.check_roles(vp.RoleData(roles=[role("aws", plain)]))
    (b,) = vp.check_roles(vp.RoleData(roles=[role("aws", inferred)]))
    assert a.evidence["wildcard_arns"] == ["arn:aws:iam::*:role/*"]
    assert (a.evidence["account_narrowed"], b.evidence["account_narrowed"]) == (False, True)
    assert a.object_path == "auth/aws/role/r"


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"auth_type": "ec2"}, ["VP-AWS-002"]),
        ({"auth_type": "ec2", "bound_region": ["us-east-1"], "bound_ami_id": ["ami-1"], "bound_vpc_id": []}, ["VP-AWS-002"]),
        ({"auth_type": "ec2", "bound_account_id": ["123456789012"]}, []),
        ({"auth_type": "ec2", "bound_vpc_id": ["vpc-1"], "bound_region": ["us-east-1"]}, []),
        ({"auth_type": "ec2", "bound_iam_role_arn": ["arn:aws:iam::123456789012:role/web"]}, []),
        ({"auth_type": "ec2", "bound_ec2_instance_id": ["i-0abc"]}, []),
        ({"auth_type": "ec2", "bound_account_id": ["123456789012"], "allow_instance_migration": True}, ["VP-AWS-004"]),
        ({"auth_type": "ec2", "bound_account_id": ["123456789012"], "allow_instance_migration": False}, []),
    ],
)
def test_aws_ec2_roles(config, expected):
    assert ids([role("aws", config)]) == expected


def test_aws_roles_still_get_token_param_rules():
    config = {"auth_type": "ec2", "bound_account_id": ["123456789012"], "token_policies": ["root"], "token_period": 3600}
    assert ids([role("aws", config)]) == ["VP-ROLE-001", "VP-ROLE-009"]


SA = "app@my-proj.iam.gserviceaccount.com"


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"type": "iam", "bound_service_accounts": ["*"], "max_jwt_exp": 900}, ["VP-GCP-001"]),
        ({"bound_service_accounts": ["*"]}, ["VP-GCP-001"]),  # type defaults to iam
        ({"type": "iam", "bound_service_accounts": ["*"], "bound_projects": ["my-proj"]}, ["VP-GCP-003"]),
        ({"type": "iam", "bound_service_accounts": [SA]}, []),  # the email pins the project
        ({"type": "iam", "bound_service_accounts": [SA], "bound_projects": ["my-proj"], "max_jwt_exp": 900}, []),
        ({"type": "iam", "bound_service_accounts": [SA], "max_jwt_exp": 901}, ["VP-GCP-004"]),
        ({"type": "iam", "bound_service_accounts": ["*"], "max_jwt_exp": 3600}, ["VP-GCP-001", "VP-GCP-004"]),
        ({"type": "iam", "bound_service_accounts": [SA], "max_jwt_exp": "bogus"}, []),
    ],
)
def test_gcp_iam_roles(config, expected):
    assert ids([role("gcp", config)]) == expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"type": "gce"}, ["VP-GCP-002"]),
        ({"type": "gce", "bound_zones": ["us-central1-a"], "bound_regions": ["us-central1"], "bound_labels": {"env": "prod"}, "bound_instance_groups": ["web"]}, ["VP-GCP-002"]),
        ({"type": "gce", "bound_service_accounts": ["*"], "bound_zones": ["us-central1-a"]}, ["VP-GCP-002"]),
        ({"type": "gce", "bound_projects": ["my-proj"]}, []),
        ({"type": "gce", "bound_service_accounts": [SA]}, []),
        ({"type": "gce", "bound_projects": ["my-proj"], "max_jwt_exp": 3600}, []),  # max_jwt_exp is iam only
    ],
)
def test_gcp_gce_roles(config, expected):
    assert ids([role("gcp", config)]) == expected


def test_gcp_evidence_and_path():
    iam = role("gcp", {"type": "iam", "bound_service_accounts": [SA], "max_jwt_exp": 3600}, name="ci")
    gce = role("gcp", {"type": "gce", "bound_zones": ["us-central1-a"], "bound_labels": {"env": "prod"}}, name="vm")
    project = role("gcp", {"type": "iam", "bound_service_accounts": ["*"], "bound_projects": ["my-proj"]}, name="p")
    a, b, c = (vp.check_roles(vp.RoleData(roles=[r]))[0] for r in (iam, gce, project))
    assert (a.rule_id, a.evidence["max_jwt_exp_seconds"], a.object_path, a.object_kind) == ("VP-GCP-004", 3600, "auth/gcp/role/ci", "gcp_role")
    assert (b.rule_id, b.evidence["bound_zones"], b.evidence["bound_labels"]) == ("VP-GCP-002", ["us-central1-a"], {"env": "prod"})
    assert (c.rule_id, c.evidence["bound_projects"]) == ("VP-GCP-003", ["my-proj"])


def test_gcp_roles_still_get_token_param_rules():
    config = {"type": "gce", "bound_projects": ["my-proj"], "token_policies": ["root"], "token_period": 3600}
    assert ids([role("gcp", config)]) == ["VP-ROLE-001", "VP-ROLE-009"]


OID = "00000000-0000-0000-0000-0000000000aa"
SUB = "00000000-0000-0000-0000-000000000001"


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"bound_service_principal_ids": ["*"]}, ["VP-AZURE-001"]),
        ({"bound_group_ids": ["*"], "bound_service_principal_ids": None}, ["VP-AZURE-001"]),
        ({"bound_service_principal_ids": ["*"], "bound_locations": ["eastus"]}, ["VP-AZURE-001"]),  # location doesn't narrow
        ({"bound_service_principal_ids": ["*"], "bound_subscription_ids": [SUB]}, []),
        ({"bound_service_principal_ids": ["*"], "bound_scale_sets": ["web"], "bound_subscription_ids": [SUB]}, []),
        ({"bound_service_principal_ids": ["*"], "bound_group_ids": [OID]}, []),  # the group narrows
        ({"bound_service_principal_ids": ["*", OID]}, []),  # "*" beside an ID is matched literally
        ({"bound_service_principal_ids": [OID]}, []),
    ],
)
def test_azure_wildcard_identity_fires_001(config, expected):
    assert ids([role("azure", config)]) == expected


@pytest.mark.parametrize(
    "config",
    [
        {"bound_locations": ["eastus"]},
        {"bound_resource_groups": ["app-rg"], "bound_subscription_ids": [SUB]},
        {"bound_service_principal_ids": ["*"], "bound_group_ids": ["*"]},
        {"bound_service_principal_ids": [], "bound_group_ids": None, "bound_scale_sets": ["web"]},  # 002 alone, not 003
    ],
)
def test_azure_role_without_identity_fires_002(config):
    assert ids([role("azure", config)]) == ["VP-AZURE-002"]


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"bound_group_ids": ["*"], "bound_resource_groups": ["app-rg"]}, ["VP-AZURE-003"]),
        ({"bound_group_ids": [OID], "bound_scale_sets": ["web"]}, ["VP-AZURE-003"]),  # a group can hold many identities
        ({"bound_group_ids": [OID], "bound_resource_groups": ["app-rg"], "bound_subscription_ids": [SUB]}, []),
        ({"bound_service_principal_ids": [OID], "bound_resource_groups": ["app-rg"]}, []),  # the SP pins the identity
        ({"bound_group_ids": [OID]}, []),
    ],
)
def test_azure_resource_group_without_subscription_fires_003(config, expected):
    assert ids([role("azure", config)]) == expected


def test_azure_evidence_and_path():
    wide = role("azure", {"bound_group_ids": ["*"], "bound_locations": ["eastus"]}, name="vm")
    dead = role("azure", {"bound_locations": ["westus"]}, name="old")
    rg = role("azure", {"bound_group_ids": [OID], "bound_resource_groups": ["app-rg"]}, name="rg")
    a, b, c = (vp.check_roles(vp.RoleData(roles=[r]))[0] for r in (wide, dead, rg))
    assert (a.rule_id, a.evidence["wildcard_field"], a.evidence["bound_locations"], a.object_path, a.object_kind) == (
        "VP-AZURE-001",
        "bound_group_ids",
        ["eastus"],
        "auth/azure/role/vm",
        "azure_role",
    )
    assert "in eastus" in a.detail
    assert (b.rule_id, b.evidence["bound_locations"], b.evidence["bound_subscription_ids"]) == ("VP-AZURE-002", ["westus"], [])
    assert (c.rule_id, c.evidence["bound_resource_groups"], c.evidence["bound_group_ids"]) == ("VP-AZURE-003", ["app-rg"], [OID])


def test_azure_roles_still_get_token_param_rules():
    config = {"bound_service_principal_ids": [OID], "token_policies": ["root"], "token_period": 3600}
    assert ids([role("azure", config)]) == ["VP-ROLE-001", "VP-ROLE-009"]


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({}, ["VP-CERT-001"]),
        ({"allowed_common_names": None, "allowed_dns_sans": [], "required_extensions": [], "ocsp_enabled": True}, ["VP-CERT-001"]),
        ({"allowed_common_names": ["svc.example.com"]}, []),
        ({"allowed_names": ["*.example.com"]}, []),
        ({"allowed_organizational_units": ["payments"]}, []),
        ({"allowed_organizations": ["Acme"]}, []),
        ({"allowed_email_sans": ["ops@example.com"]}, []),
        ({"allowed_uri_sans": ["spiffe://example.org/web"]}, []),
        ({"required_extensions": ["1.2.3.4:*"]}, []),
        ({"allowed_common_names": ["*"]}, ["VP-CERT-002"]),
        ({"allowed_dns_sans": ["*.*"]}, ["VP-CERT-002"]),
        ({"allowed_names": ["*.com"]}, ["VP-CERT-002"]),
        ({"allowed_common_names": ["web.example.com", "*"]}, ["VP-CERT-002"]),  # values are ORed
        ({"allowed_common_names": ["*"], "allowed_dns_sans": ["*.io"]}, ["VP-CERT-002"]),
        ({"allowed_common_names": ["*"], "allowed_organizational_units": ["payments"]}, []),  # fields are ANDed
        ({"allowed_common_names": ["*"], "allowed_dns_sans": ["web.example.com"]}, []),
        ({"allowed_common_names": ["*.example.com", "web-*"]}, []),
    ],
)
def test_cert_roles(config, expected):
    assert ids([role("cert", config)]) == expected


def test_cert_catch_all_evidence_and_path():
    (f,) = vp.check_roles(vp.RoleData(roles=[role("cert", {"allowed_common_names": ["*", "web"], "allowed_dns_sans": ["*.com"]}, name="web")]))
    assert f.rule_id == "VP-CERT-002"
    assert f.evidence["broad_patterns"] == {"allowed_common_names": ["*"], "allowed_dns_sans": ["*.com"]}
    assert f.object_path == "auth/cert/certs/web"
    assert f.object_kind == "cert_role"


def test_cert_roles_still_get_token_param_rules():
    config = {"allowed_common_names": ["svc.example.com"], "token_policies": ["root"], "token_period": 3600}
    assert ids([role("cert", config)]) == ["VP-ROLE-001", "VP-ROLE-009"]
