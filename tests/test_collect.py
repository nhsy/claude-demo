"""Collectors: coverage classification and field allowlisting, driven by a FakeReader."""

import pytest
import requests
import vault_posture as vp
from conftest import COMMUNITY_ROUTES, SECRET_MARKERS, FakeReader, enterprise_only, not_found, ok, unsupported_path
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
    assert coverage.scopes == [{"scope": "x", "status": "error", "detail": "ConnectionError"}]
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
    assert reader.calls == [("sys/quotas/rate-limit", True)]
