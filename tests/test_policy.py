"""The generated token policies: no drift from scripts/gen_policies.py, read/list only, and every
path the script reads (in every namespace level) is granted. Uses the script's own ACL evaluator,
which tests/test_access.py and the integration tests check against Vault."""

import importlib.util

import pytest
import vault_posture as vp
from conftest import COMMUNITY_ROUTES, POLICY_DIR, ROOT, FakeReader, mounts, ok

BASE = POLICY_DIR / "vault-posture-readonly.hcl"
PKI = POLICY_DIR / "vault-posture-pki-reader.hcl"


def load(*files):
    return [rule for f in files for rule in vp.parse_policy(f.stem, f.read_text())]


def test_policies_match_the_generator():
    spec = importlib.util.spec_from_file_location("gen_policies", ROOT / "scripts/gen_policies.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for path, text in gen.rendered().items():
        assert path.read_text() == text, f"{path.name} is stale: run `task policies`"


@pytest.mark.parametrize("policy", [BASE, PKI])
def test_policy_only_grants_read_list_or_deny(policy):
    rules = load(policy)
    assert rules, "no path blocks parsed"
    for rule in rules:
        caps = set(rule.capabilities)
        if rule.path == "sys/audit":  # Vault requires sudo even to list audit devices
            assert caps == {"read", "sudo"}
            continue
        assert caps <= {"read", "list"} or caps == {"deny"}, rule.path


def all_reads():
    """Every (namespace, path, is_list) the collectors issue, on an Enterprise-shaped tree three levels
    deep, with auth and PKI mounts one to three path segments deep (MOUNT_DEPTH in gen_policies.py)."""
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/auth", False)] = ok({**COMMUNITY_ROUTES[("sys/auth", False)]["data"], "k8s/prod/": {"type": "kubernetes", "config": {}}, "ldap/": {"type": "ldap", "config": {}}})
    for segment in ("groups", "users"):
        routes[(f"auth/ldap/{segment}", True)] = ok({"keys": ["admins"]})
        routes[(f"auth/ldap/{segment}/admins", False)] = ok({"policies": ["root"]})
    routes[("auth/ldap/config", False)] = ok({"url": "ldaps://ldap.example.com"})
    routes[("auth/k8s/prod/role", True)] = ok({"keys": ["web"]})
    routes[("auth/k8s/prod/role/web", False)] = ok({"bound_service_account_names": ["web"]})
    routes[("sys/mounts", False)] = ok({**COMMUNITY_ROUTES[("sys/mounts", False)]["data"], "pki/int/": {"type": "pki", "config": {}}})
    for path in ("pki/int/config/auto-tidy", "pki/int/config/crl", "pki/int/config/urls", "pki/int/issuer/i"):
        routes[(path, False)] = ok({})
    routes[("pki/int/issuers", True)] = ok({"keys": ["i"]})
    routes[("sys/quotas/lease-count", True)] = ok({"keys": ["global"]})
    routes[("sys/quotas/lease-count/global", False)] = ok({"name": "global", "type": "lease-count", "path": "", "max_leases": 1000})
    routes[("sys/namespaces", True)] = ok({"keys": ["a/"]})
    routes[("auth/token/roles", True)] = ok({"keys": ["ops"]})
    routes[("auth/token/roles/ops", False)] = ok({"allowed_policies": ["app"]})
    for ns, child in (("a", "b/"), ("a/b", "c/")):
        routes[(ns, "sys/namespaces", True)] = ok({"keys": [child]})
    for ns in ("a", "a/b", "a/b/c"):
        routes[(ns, "sys/auth", False)] = mounts(approle="approle", aws="aws", gcp="gcp", azure="azure", token="ns_token", **{"apps/team/x": "approle", "cert/x": "cert", "ldap/corp": "ldap"})
        routes[(ns, "auth/gcp/role", True)] = ok({"keys": ["gce"]})
        routes[(ns, "auth/gcp/role/gce", False)] = ok({"type": "gce", "bound_projects": ["my-proj"]})
        routes[(ns, "auth/azure/role", True)] = ok({"keys": ["vm"]})
        routes[(ns, "auth/azure/role/vm", False)] = ok({"bound_service_principal_ids": ["00000000-0000-0000-0000-000000000001"]})
        routes[(ns, "auth/cert/x/certs", True)] = ok({"keys": ["web"]})
        routes[(ns, "auth/cert/x/certs/web", False)] = ok({"allowed_common_names": ["web.example.com"]})
        for segment in ("groups", "users"):
            routes[(ns, f"auth/ldap/corp/{segment}", True)] = ok({"keys": ["ops"]})
            routes[(ns, f"auth/ldap/corp/{segment}/ops", False)] = ok({"policies": ["app"]})
        routes[(ns, "auth/ldap/corp/config", False)] = ok({"url": "ldaps://ldap.example.com"})
        routes[(ns, "auth/aws/role", True)] = ok({"keys": ["ec2"]})
        routes[(ns, "auth/aws/role/ec2", False)] = ok({"auth_type": "ec2", "bound_account_id": ["123456789012"]})
        for mount in ("approle", "apps/team/x"):
            routes[(ns, f"auth/{mount}/role", True)] = ok({"keys": ["svc"]})
            routes[(ns, f"auth/{mount}/role/svc", False)] = ok({"bind_secret_id": True})
        routes[(ns, "auth/token/roles", True)] = ok({"keys": ["t"]})
        routes[(ns, "auth/token/roles/t", False)] = ok({"allowed_policies": ["x"]})
        routes[(ns, "sys/mounts", False)] = mounts(pki_int="pki", **{"pki/int": "pki", "ca/x/y": "pki"})
        for mount in ("pki_int", "pki/int", "ca/x/y"):
            for path in ("config/auto-tidy", "config/crl", "config/urls", "issuer/i"):
                routes[(ns, f"{mount}/{path}", False)] = ok({})
            routes[(ns, f"{mount}/issuers", True)] = ok({"keys": ["i"]})
    reader = FakeReader(routes)
    reader.get("auth/token/lookup-self")
    vp.collect_quotas(reader, vp.Coverage())
    vp.collect_security(reader, vp.Coverage())
    namespaces = vp.discover_namespaces(reader, vp.Coverage())
    assert namespaces == ["", "a", "a/b", "a/b/c"]
    vp.collect_roles(reader, vp.Coverage(), namespaces)
    vp.collect_pki(reader, vp.Coverage(), namespaces)
    calls = set(reader.calls)
    deep = {
        ("", "auth/k8s/prod/role/web", False),
        ("", "pki/int/issuer/i", False),
        ("a/b/c", "auth/apps/team/x/role/svc", False),
        ("a/b/c", "ca/x/y/issuers", True),
        ("a/b", "auth/cert/x/certs/web", False),
        ("", "auth/ldap/groups/admins", False),
        ("a/b/c", "auth/ldap/corp/users/ops", False),
        ("a/b", "auth/ldap/corp/config", False),
    }
    assert deep <= calls, "the multi-segment mounts were not read"
    return calls


def acl_path(namespace, path, is_list):
    # A root-namespace token is checked against "<namespace>/<path>"; lists against the path plus "/".
    full = f"{namespace}/{path}" if namespace else path
    return full + "/" if is_list else full


def test_every_read_is_granted_by_base_plus_pki():
    rules = load(BASE, PKI)
    for namespace, path, is_list in all_reads():
        needed = "list" if is_list else "read"
        result = vp.effective_capabilities(rules, acl_path(namespace, path, is_list))
        assert needed in result["capabilities"], f"{needed} on {acl_path(namespace, path, is_list)}"


def test_pki_reads_need_the_addon():
    rules = load(BASE)
    pki_reads = [(ns, p, lst) for ns, p, lst in all_reads() if "pki_int/" in p or p == "sys/mounts"]
    assert pki_reads
    for namespace, path, is_list in pki_reads:
        assert vp.effective_capabilities(rules, acl_path(namespace, path, is_list))["capabilities"] == ["deny"], path


@pytest.mark.parametrize(
    "path",
    [
        "database/creds/app",
        "pki/issue/web",
        "ssh/sign/ops",
        "sys/wrapping/unwrap",
        "auth/approle/role/svc/role-id",
        "auth/approle/role/svc/secret-id",
        "auth/approle/role/svc/secret-id/",
        "team-a/auth/approle/role/svc/role-id",
        "auth/aws/config/client",
        "auth/k8s/prod/role/x/role-id",
        "auth/apps/team/x/role/svc/secret-id",
        "auth/apps/team/x/role/svc/secret-id/",
        "team-a/auth/k8s/prod/role/x/role-id",
        "a/b/c/d/e/auth/apps/team/x/role/svc/secret-id-accessor/lookup",
        # A role named "role" on a shallower mount must not fall under a deeper mount's role grant.
        "auth/approle/role/role/role-id",
        "auth/approle/role/role/secret-id",
        "team-a/auth/approle/role/role/role-id",
        "team-a/auth/approle/role/role/secret-id",
        # Nor an AppRole role named "certs" under a deeper mount's cert grant (auth/+/+/certs/+).
        "auth/approle/role/certs/role-id",
        "auth/approle/role/certs/secret-id",
        "team-a/auth/approle/role/certs/secret-id",
        # Or named "groups"/"users" under a deeper mount's LDAP mapping grants (auth/+/+/users/+).
        "auth/approle/role/groups/role-id",
        "auth/approle/role/users/secret-id",
        "team-a/auth/approle/role/users/role-id",
        "secret/data/app",
        "sys/policies/acl/admin",
        "auth/token/create",
        "sys/generate-root/update",
    ],
)
def test_sensitive_paths_are_never_readable(path):
    caps = vp.effective_capabilities(load(BASE, PKI), path)["capabilities"]
    assert caps == ["deny"], path


@pytest.mark.parametrize("mount", ["ldap", "gcp", "azure", "kubernetes", "corp/ldap", "a/b/c"])
@pytest.mark.parametrize("namespace", ["", "team-a/", "a/b/c/d/e/"])
def test_auth_config_grant_reaches_config_only(mount, namespace):
    # auth/{m}config is read on every method (gen_policies.py lists what each returns); nothing below it.
    rules = load(BASE, PKI)
    assert vp.effective_capabilities(rules, f"{namespace}auth/{mount}/config")["capabilities"] == ["read"]
    for below in ("client", "certificate/x", "rotate-root"):
        assert vp.effective_capabilities(rules, f"{namespace}auth/{mount}/config/{below}")["capabilities"] == ["deny"], below


def test_audit_devices_get_sudo_and_nothing_else_does():
    rules = load(BASE, PKI)
    assert sorted(vp.effective_capabilities(rules, "sys/audit")["capabilities"]) == ["read", "sudo"]
    assert [r.path for r in rules if "sudo" in r.capabilities] == ["sys/audit"]
