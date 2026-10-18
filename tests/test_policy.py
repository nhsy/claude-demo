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
        assert caps <= {"read", "list"} or caps == {"deny"}, rule.path


def all_reads():
    """Every (namespace, path, is_list) the collectors issue, on an Enterprise-shaped tree three levels deep."""
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/quotas/lease-count", True)] = ok({"keys": ["global"]})
    routes[("sys/quotas/lease-count/global", False)] = ok({"name": "global", "type": "lease-count", "path": "", "max_leases": 1000})
    routes[("sys/namespaces", True)] = ok({"keys": ["a/"]})
    routes[("auth/token/roles", True)] = ok({"keys": ["ops"]})
    routes[("auth/token/roles/ops", False)] = ok({"allowed_policies": ["app"]})
    for ns, child in (("a", "b/"), ("a/b", "c/")):
        routes[(ns, "sys/namespaces", True)] = ok({"keys": [child]})
    for ns in ("a", "a/b", "a/b/c"):
        routes[(ns, "sys/auth", False)] = mounts(approle="approle", aws="aws", token="ns_token")
        routes[(ns, "auth/aws/role", True)] = ok({"keys": ["ec2"]})
        routes[(ns, "auth/aws/role/ec2", False)] = ok({"auth_type": "ec2", "bound_account_id": ["123456789012"]})
        routes[(ns, "auth/approle/role", True)] = ok({"keys": ["svc"]})
        routes[(ns, "auth/approle/role/svc", False)] = ok({"bind_secret_id": True})
        routes[(ns, "auth/token/roles", True)] = ok({"keys": ["t"]})
        routes[(ns, "auth/token/roles/t", False)] = ok({"allowed_policies": ["x"]})
        routes[(ns, "sys/mounts", False)] = mounts(pki_int="pki")
        for path in ("pki_int/config/auto-tidy", "pki_int/config/crl", "pki_int/config/urls", "pki_int/issuer/i"):
            routes[(ns, path, False)] = ok({})
        routes[(ns, "pki_int/issuers", True)] = ok({"keys": ["i"]})
    reader = FakeReader(routes)
    reader.get("auth/token/lookup-self")
    vp.collect_quotas(reader, vp.Coverage())
    vp.collect_security(reader, vp.Coverage())
    namespaces = vp.discover_namespaces(reader, vp.Coverage())
    assert namespaces == ["", "a", "a/b", "a/b/c"]
    vp.collect_roles(reader, vp.Coverage(), namespaces)
    vp.collect_pki(reader, vp.Coverage(), namespaces)
    return set(reader.calls)


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
        "secret/data/app",
        "sys/policies/acl/admin",
        "auth/token/create",
        "sys/generate-root/update",
    ],
)
def test_sensitive_paths_are_never_readable(path):
    caps = vp.effective_capabilities(load(BASE, PKI), path)["capabilities"]
    assert caps == ["deny"], path
