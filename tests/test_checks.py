"""Pure rule checks: each rule fires on its trigger and stays quiet on its control."""

from datetime import timedelta

import pytest
import vault_posture as vp
from conftest import NOW


def ids(findings):
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------- quotas


def quota(name, path="", qtype="rate-limit"):
    return {"name": name, "type": qtype, "path": path}


def test_no_quotas_fires_001_and_002():
    found = vp.check_quotas(vp.QuotaData(config={}, rate_limit=[], lease_count=[]))
    assert ids(found) == ["VP-QUOTA-001", "VP-QUOTA-002"]
    assert {f.object_path for f in found} == {"rate-limit", "lease-count"}


def test_unjudged_quota_types_are_skipped():
    # None = unreadable or Enterprise-only on Community: never reported as "missing".
    assert vp.check_quotas(vp.QuotaData(config=None, rate_limit=None, lease_count=None)) == []


def test_path_scoped_quotas_only_fire_003():
    data = vp.QuotaData(
        config={"enable_rate_limit_audit_logging": True},
        rate_limit=[quota("login", "auth/userpass/"), quota("team", "team-a/")],
        lease_count=[quota("global", "", "lease-count")],
    )
    found = vp.check_quotas(data)
    assert ids(found) == ["VP-QUOTA-003"]
    assert found[0].evidence["quota_type"] == "rate-limit"
    assert found[0].evidence["paths"] == ["auth/userpass/", "team-a/"]


def test_cluster_wide_quotas_are_quiet():
    data = vp.QuotaData(
        config={"enable_rate_limit_audit_logging": True},
        rate_limit=[quota("global")],
        lease_count=[quota("global", "", "lease-count")],
    )
    assert vp.check_quotas(data) == []


def builtin_default(max_leases=300000):
    return {"name": "default", "type": "lease-count", "path": "", "max_leases": max_leases}


def test_builtin_default_lease_quota_fires_002():
    # Enterprise 1.16+ ships this quota on every new install: it isn't an operator's limit.
    found = vp.check_quotas(vp.QuotaData(config=None, rate_limit=None, lease_count=[builtin_default()]))
    assert ids(found) == ["VP-QUOTA-002"]
    assert found[0].evidence == {"builtin_default": True, "max_leases": 300000}


def test_tuned_default_lease_quota_is_quiet():
    assert vp.check_quotas(vp.QuotaData(config=None, rate_limit=None, lease_count=[builtin_default(5000)])) == []


def test_global_lease_quota_beside_builtin_default_is_quiet():
    data = vp.QuotaData(config=None, rate_limit=None, lease_count=[builtin_default(), quota("global", "", "lease-count")])
    assert vp.check_quotas(data) == []


def test_path_scoped_lease_quotas_with_builtin_default_fire_003():
    data = vp.QuotaData(config=None, rate_limit=None, lease_count=[builtin_default(), quota("pki", "pki/", "lease-count")])
    found = vp.check_quotas(data)
    assert ids(found) == ["VP-QUOTA-003"]
    assert found[0].evidence["quota_type"] == "lease-count"
    assert found[0].evidence["quotas"] == 1
    assert found[0].evidence["paths"] == ["pki/"]


@pytest.mark.parametrize(("audit_logging", "expected"), [(False, ["VP-QUOTA-004"]), (True, [])])
def test_rate_limit_audit_logging(audit_logging, expected):
    data = vp.QuotaData(config={"enable_rate_limit_audit_logging": audit_logging}, rate_limit=[quota("global")], lease_count=None)
    assert ids(vp.check_quotas(data)) == expected


def test_audit_logging_not_judged_without_rate_limit_quotas():
    data = vp.QuotaData(config={"enable_rate_limit_audit_logging": False}, rate_limit=[], lease_count=None)
    assert ids(vp.check_quotas(data)) == ["VP-QUOTA-001"]


# --------------------------------------------------------------------------- security


def quiet_security(**overrides):
    base = {
        "generate_root": {"started": False, "progress": 0, "required": 3},
        "generate_recovery_token": None,
        "rekey": {"started": False, "progress": 0, "required": 3},
        "rekey_recovery": None,
        "key_status": {"term": 4, "install_time": (NOW - timedelta(days=30)).isoformat(), "encryptions": 10},
        "rotate_config": {"enabled": True, "interval": 30 * 24 * 3600, "max_operations": 3865470566},
        "plugins": [{"name": "kv", "type": "secret", "version": "v0.1.0+builtin", "builtin": True}],
        "audit_devices": [audit_device("file/"), audit_device("syslog/", "syslog")],
        "config_state": {"max_lease_ttl": 0, "listeners": [{"type": "tcp", "address": "0.0.0.0:8200"}]},
    }
    base.update(overrides)
    return vp.SecurityData(**base)


def audit_device(path, kind="file", **options):
    return {"path": path, "type": kind, "local": False, "options": options}


def test_quiet_security_has_no_findings():
    assert vp.check_security(quiet_security(), NOW) == []


@pytest.mark.parametrize(
    ("field", "rule", "path"),
    [
        ("generate_root", "VP-SEC-001", "sys/generate-root/attempt"),
        ("generate_recovery_token", "VP-SEC-001", "sys/generate-recovery-token/attempt"),
        ("rekey", "VP-SEC-002", "sys/rekey/init"),
        ("rekey_recovery", "VP-SEC-002", "sys/rekey-recovery-key/init"),
    ],
)
def test_seal_operations_in_progress(field, rule, path):
    found = vp.check_security(quiet_security(**{field: {"started": True, "progress": 2, "required": 3}}), NOW)
    assert ids(found) == [rule]
    assert found[0].object_path == path
    assert "2 of 3" in found[0].detail


def test_old_barrier_key_fires_003_with_nanosecond_timestamp():
    found = vp.check_security(quiet_security(key_status={"term": 1, "install_time": "2024-01-02T03:04:05.123456789Z"}), NOW)
    assert ids(found) == ["VP-SEC-003"]
    assert found[0].evidence["age_days"] == (NOW - vp.parse_time("2024-01-02T03:04:05Z")).days
    assert found[0].evidence["threshold_days"] == vp.KEY_AGE_WARNING_DAYS


def test_key_age_threshold_is_configurable():
    data = quiet_security()  # 30 days old
    assert ids(vp.check_security(data, NOW, key_age_days=7)) == ["VP-SEC-003"]


def test_unparseable_install_time_is_ignored():
    assert vp.check_security(quiet_security(key_status={"term": 1, "install_time": "not-a-time"}), NOW) == []


@pytest.mark.parametrize("rotate", [{"enabled": True, "interval": 0}, {"enabled": False, "interval": 86400}])
def test_rotation_without_interval_fires_004(rotate):
    assert ids(vp.check_security(quiet_security(rotate_config=rotate), NOW)) == ["VP-SEC-004"]


def test_external_plugins():
    plugins = [
        {"name": "kv", "type": "secret", "version": "v0.1.0+builtin", "builtin": True},
        {"name": "custom-db", "type": "database", "version": "", "builtin": False},
        {"name": "venafi", "type": "secret", "version": "v1.2.3", "builtin": False},
    ]
    found = vp.check_security(quiet_security(plugins=plugins), NOW)
    assert ids(found) == ["VP-PLUG-001", "VP-PLUG-002"]
    unversioned = next(f for f in found if f.rule_id == "VP-PLUG-001")
    assert unversioned.object_path == "database/custom-db"
    catalog = next(f for f in found if f.rule_id == "VP-PLUG-002")
    assert catalog.evidence == {"plugins": ["database/custom-db", "secret/venafi"], "count": 2}


def test_no_audit_device_fires_001():
    found = vp.check_security(quiet_security(audit_devices=[]), NOW)
    assert ids(found) == ["VP-AUDIT-001"]
    assert found[0].object_path == "sys/audit"


def test_single_audit_device_fires_002():
    found = vp.check_security(quiet_security(audit_devices=[audit_device("file/")]), NOW)
    assert ids(found) == ["VP-AUDIT-002"]
    assert found[0].evidence == {"device_path": "file/", "device_type": "file"}


@pytest.mark.parametrize(
    ("options", "log_raw", "hmac_accessor"),
    [
        ({"log_raw": "true"}, True, True),  # Vault returns options as strings
        ({"hmac_accessor": "false"}, False, False),
        ({"log_raw": True, "hmac_accessor": False}, True, False),
    ],
)
def test_raw_or_unhashed_audit_device_fires_003(options, log_raw, hmac_accessor):
    found = vp.check_security(quiet_security(audit_devices=[audit_device("raw/", **options), audit_device("file/")]), NOW)
    assert ids(found) == ["VP-AUDIT-003"]
    assert found[0].object_path == "raw/"
    assert found[0].evidence == {"device_type": "file", "log_raw": log_raw, "hmac_accessor": hmac_accessor}


@pytest.mark.parametrize("options", [{}, {"log_raw": "false", "hmac_accessor": "true"}, {"log_raw": "maybe"}])
def test_audit_options_at_their_defaults_are_quiet(options):
    assert vp.check_security(quiet_security(audit_devices=[audit_device("a/", **options), audit_device("b/")]), NOW) == []


def config(*listeners, max_lease_ttl=0):
    return {"max_lease_ttl": max_lease_ttl, "listeners": list(listeners)}


@pytest.mark.parametrize("address", ["0.0.0.0:8200", "[::]:8200", "10.0.0.5:8200", "vault.example.com:8200"])
def test_plaintext_listener_on_network_fires_cfg_001(address):
    found = vp.check_security(quiet_security(config_state=config({"type": "tcp", "address": address, "tls_disable": True})), NOW)
    assert ids(found) == ["VP-CFG-001"]
    assert found[0].object_path == address


@pytest.mark.parametrize(
    "listener",
    [
        {"type": "tcp", "address": "127.0.0.1:8200", "tls_disable": True},
        {"type": "tcp", "address": "[::1]:8200", "tls_disable": "true"},
        {"type": "tcp", "address": "localhost:8200", "tls_disable": True},
        {"type": "tcp", "address": "0.0.0.0:8200", "tls_disable": False},
        {"type": "tcp", "address": "0.0.0.0:8200"},
        {"type": "unix", "address": "/run/vault.sock", "tls_disable": True},
    ],
)
def test_loopback_unix_or_tls_listeners_are_quiet(listener):
    assert vp.check_security(quiet_security(config_state=config(listener)), NOW) == []


def test_string_tls_disable_on_network_fires_cfg_001():
    assert ids(vp.check_security(quiet_security(config_state=config({"type": "tcp", "address": "0.0.0.0:8200", "tls_disable": "true"})), NOW)) == ["VP-CFG-001"]


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ({"unauthenticated_metrics_access": True}, ["unauthenticated_metrics_access"]),
        ({"unauthenticated_pprof_access": "true"}, ["unauthenticated_pprof_access"]),
        ({"unauthenticated_metrics_access": "true", "unauthenticated_pprof_access": True}, ["unauthenticated_metrics_access", "unauthenticated_pprof_access"]),
    ],
)
def test_unauthenticated_metrics_or_pprof_fires_cfg_002(flags, expected):
    found = vp.check_security(quiet_security(config_state=config({"type": "tcp", "address": "127.0.0.1:8202", **flags})), NOW)
    assert ids(found) == ["VP-CFG-002"]
    assert found[0].evidence == {"address": "127.0.0.1:8202", "flags": expected}


def test_authenticated_metrics_are_quiet():
    listener = {"type": "tcp", "address": "127.0.0.1:8200", "unauthenticated_metrics_access": "false", "unauthenticated_pprof_access": False}
    assert vp.check_security(quiet_security(config_state=config(listener)), NOW) == []


@pytest.mark.parametrize("ttl", [31536000, "8760h", 769 * 3600, "769h0m0s"])
def test_long_max_lease_ttl_fires_cfg_003(ttl):
    found = vp.check_security(quiet_security(config_state=config(max_lease_ttl=ttl)), NOW)
    assert ids(found) == ["VP-CFG-003"]
    assert found[0].evidence["threshold_seconds"] == 768 * 3600


@pytest.mark.parametrize("ttl", [0, None, 768 * 3600, "768h", "24h", "not-a-ttl"])
def test_default_or_short_max_lease_ttl_is_quiet(ttl):
    assert vp.check_security(quiet_security(config_state=config(max_lease_ttl=ttl)), NOW) == []


def test_unreadable_security_data_is_not_judged():
    assert vp.check_security(vp.SecurityData(), NOW) == []


# --------------------------------------------------------------------------- catalogue


def test_every_rule_is_documented():
    rules_md = (vp.Path(vp.__file__).resolve().parents[1] / "references/rules.md").read_text()
    for rule_id, rule in vp.RULES.items():
        assert f"| {rule_id} | {rule.severity} |" in rules_md, rule_id


def test_fingerprint_is_stable_and_ignores_evidence():
    a = vp.finding("VP-QUOTA-001", "quota_type", "rate-limit", "x", n=1)
    b = vp.finding("VP-QUOTA-001", "quota_type", "rate-limit", "y", n=2)
    assert a.fingerprint == b.fingerprint
    assert len(a.fingerprint) == 16
