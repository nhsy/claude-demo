"""Collectors: coverage classification and field allowlisting, driven by a FakeReader."""

import pytest
import requests
import vault_posture as vp
from conftest import COMMUNITY_ROUTES, SECRET_MARKERS, FakeReader, enterprise_only, mounts, not_found, ok, unsupported_path
from hvac import exceptions as hvac_exc


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (hvac_exc.Forbidden(errors=["permission denied"]), vp.DENIED),
        (enterprise_only(), vp.UNSUPPORTED),
        (unsupported_path(), vp.NOT_APPLICABLE),
        (hvac_exc.InvalidRequest(errors=["recovery rekeying not supported"]), vp.NOT_APPLICABLE),
        (not_found(), vp.ABSENT),
        (hvac_exc.InvalidRequest(errors=["bad request"]), vp.ERROR),
        (hvac_exc.InternalServerError(errors=["boom"]), vp.ERROR),
    ],
)
def test_classify(exc, status):
    assert vp.classify(exc) == status


def test_attempt_records_error_detail_without_message_text():
    coverage = vp.Coverage()

    def boom():
        raise requests.exceptions.ConnectionError("http://secret-host.internal:8200 refused")

    assert vp.attempt(coverage, "x", boom) == (vp.ERROR, None)
    assert coverage.scopes == [{"namespace": "/", "scope": "x", "status": "error", "detail": "ConnectionError"}]
    assert not coverage.complete


def test_collect_quotas_community(community_reader):
    coverage = vp.Coverage()
    data = vp.collect_quotas(community_reader, coverage)
    assert data.config == {"enable_rate_limit_audit_logging": False, "enable_rate_limit_response_headers": False}
    assert data.rate_limit == [{"name": "login", "type": "rate-limit", "path": "auth/userpass/", "role": "", "rate": 10, "interval": 1, "block_interval": 0, "inheritable": False}]
    assert data.lease_count is None
    assert coverage.status("quotas.lease-count") == vp.UNSUPPORTED
    assert coverage.complete


def test_collect_quotas_empty_list_is_absent_not_a_gap():
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/quotas/rate-limit", True)] = not_found()
    coverage = vp.Coverage()
    data = vp.collect_quotas(FakeReader(routes), coverage)
    assert data.rate_limit == []
    assert coverage.status("quotas.rate-limit") == vp.ABSENT
    assert coverage.complete


def test_collect_quotas_denied_quota_body_keeps_name():
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/quotas/rate-limit/login", False)] = hvac_exc.Forbidden()
    coverage = vp.Coverage()
    data = vp.collect_quotas(FakeReader(routes), coverage)
    assert data.rate_limit == [{"name": "login"}]
    assert coverage.status("quotas.rate-limit.login") == vp.DENIED
    assert not coverage.complete


def test_collect_security_allowlists_fields(community_reader):
    coverage = vp.Coverage()
    data = vp.collect_security(community_reader, coverage)
    assert data.generate_root == {"started": True, "progress": 1, "required": 3}
    assert data.rekey == {"started": True, "progress": 1, "required": 3}
    assert data.generate_recovery_token is None
    assert data.rekey_recovery is None
    assert data.key_status == {"term": 1, "install_time": "2024-01-02T03:04:05.123456789Z", "encryptions": 42}
    assert [p["name"] for p in data.plugins] == ["approle", "kv", "custom-db"]
    assert not any(marker in repr(data) for marker in SECRET_MARKERS)
    assert coverage.status("security.generate_recovery_token") == vp.NOT_APPLICABLE
    assert coverage.status("security.rekey_recovery") == vp.NOT_APPLICABLE
    assert coverage.complete


def test_collect_security_denied_catalog():
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/plugins/catalog", False)] = hvac_exc.Forbidden()
    coverage = vp.Coverage()
    data = vp.collect_security(FakeReader(routes), coverage)
    assert data.plugins is None
    assert coverage.status("security.plugin_catalog") == vp.DENIED


def test_reader_data_unwraps_envelope_and_raw_bodies():
    reader = FakeReader({("wrapped", False): ok({"a": 1}), ("raw", False): {"term": 2}})
    assert reader.data("wrapped") == {"a": 1}
    assert reader.data("raw") == {"term": 2}


def test_reader_list_uses_get_with_list_param():
    reader = FakeReader({("sys/quotas/rate-limit", True): ok({"keys": ["a", "b"]})})
    assert reader.list("sys/quotas/rate-limit") == ["a", "b"]
    assert reader.calls == [("", "sys/quotas/rate-limit", True)]


# --------------------------------------------------------------------------- namespaces


def namespace_routes():
    return {
        ("sys/namespaces", True): ok({"keys": ["team-b/", "team-a/"]}),
        ("team-a", "sys/namespaces", True): ok({"keys": ["prod/"]}),
        ("team-a/prod", "sys/namespaces", True): not_found(),
        ("team-b", "sys/namespaces", True): hvac_exc.Forbidden(),
    }


def test_discover_namespaces_walks_breadth_first():
    coverage = vp.Coverage()
    found = vp.discover_namespaces(FakeReader(namespace_routes()), coverage)
    assert found == ["", "team-a", "team-b", "team-a/prod"]
    assert coverage.status("namespaces", "team-b") == vp.DENIED
    assert coverage.status("namespaces", "team-a/prod") == vp.ABSENT
    assert not coverage.complete


def test_discover_namespaces_from_a_start_namespace():
    found = vp.discover_namespaces(FakeReader(namespace_routes()), vp.Coverage(), "team-a")
    assert found == ["team-a", "team-a/prod"]


def test_discover_namespaces_stops_at_policy_depth():
    deep = "a/b/c/d/e"
    reader = FakeReader({})
    assert vp.discover_namespaces(reader, vp.Coverage(), deep) == [deep]
    assert reader.calls == []  # the policy grants no sys/namespaces list at depth 5


def test_discover_namespaces_on_community_is_root_only(community_reader):
    coverage = vp.Coverage()
    assert vp.discover_namespaces(community_reader, coverage) == [""]
    assert coverage.status("namespaces") == vp.UNSUPPORTED
    assert coverage.complete


def test_mounts_of_keeps_mount_entries_only():
    reader = FakeReader({("sys/auth", False): {"token/": {"type": "token"}, "request_id": "x", "data": {"token/": {"type": "token"}}}})
    assert vp.mounts_of(reader, vp.Coverage(), "auth", "") == {"token/": "token"}


# --------------------------------------------------------------------------- roles and pki


def test_collect_roles_allowlists_fields(community_reader):
    coverage = vp.Coverage()
    data = vp.collect_roles(community_reader, coverage, [""])
    assert [(r.mount, r.source, r.name) for r in data.roles] == [("jwt/", "jwt", "ci"), ("kubernetes/", "kubernetes", "any")]
    assert "role_id" not in data.roles[0].config
    assert coverage.status("roles.token/") == vp.ABSENT
    assert coverage.status("roles.userpass/") is None  # not a role-based method
    assert coverage.complete


def test_collect_roles_maps_oidc_and_namespaced_token_mounts():
    routes = {
        ("team-a", "sys/auth", False): mounts(oidc="oidc", token="ns_token"),
        ("team-a", "auth/oidc/role", True): ok({"keys": ["sso"]}),
        ("team-a", "auth/oidc/role/sso", False): ok({"role_type": "oidc", "verbose_oidc_logging": True}),
        ("team-a", "auth/token/roles", True): ok({"keys": ["svc"]}),
        ("team-a", "auth/token/roles/svc", False): ok({"allowed_policies": ["root"], "orphan": True}),
    }
    data = vp.collect_roles(FakeReader(routes), vp.Coverage(), ["team-a"])
    assert [(r.namespace, r.source, r.path) for r in data.roles] == [("team-a", "jwt", "auth/oidc/role/sso"), ("team-a", "token", "auth/token/roles/svc")]


def test_collect_roles_denied_role_body_is_a_gap():
    routes = dict(COMMUNITY_ROUTES)
    routes[("auth/jwt/role/ci", False)] = hvac_exc.Forbidden()
    coverage = vp.Coverage()
    data = vp.collect_roles(FakeReader(routes), coverage, [""])
    assert [r.name for r in data.roles] == ["any"]
    assert coverage.status("roles.jwt/ci") == vp.DENIED


def test_collect_pki_parses_certificate_and_drops_pem(community_reader):
    coverage = vp.Coverage()
    data = vp.collect_pki(community_reader, coverage, [""])
    assert [m.mount for m in data.mounts] == ["pki/"]
    issuer = data.issuers[0]
    assert issuer.issuer_id == "id-1"
    assert issuer.cert["common_name"] == "Fixture CA"
    assert issuer.cert["key_type"] == "rsa" and issuer.cert["key_bits"] == 2048
    assert "certificate" not in issuer.config and "BEGIN CERTIFICATE" not in repr(data)
    assert coverage.complete


def test_collect_pki_without_addon_is_a_gap():
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/mounts", False)] = hvac_exc.Forbidden()
    coverage = vp.Coverage()
    data = vp.collect_pki(FakeReader(routes), coverage, [""])
    assert data.mounts == [] and data.issuers == []
    assert coverage.status("mounts") == vp.DENIED
