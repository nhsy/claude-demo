"""PKI checks: issuer expiry windows, key strength, AIA, tidy, revocation, leaf behaviour."""

import pytest
import vault_posture as vp
from conftest import NOW, make_pem


def issuer(cert=None, mount="pki/", **config):
    return vp.Issuer("", mount, "id-1", {"issuer_name": "root", "leaf_not_after_behavior": "err", "issuing_certificates": ["http://ca"], **config}, cert)


def cert_facts(days_left=400, key_type="rsa", key_bits=2048, signature_hash="sha256"):
    from datetime import timedelta

    return {"common_name": "CA", "not_after": vp.iso(NOW + timedelta(days=days_left)), "key_type": key_type, "key_bits": key_bits, "signature_hash": signature_hash}


def healthy_mount(**overrides):
    base = {"auto_tidy": {"enabled": True}, "crl": {"disable": False, "ocsp_disable": False}, "urls": {"issuing_certificates": []}}
    base.update(overrides)
    return vp.PkiMount("", "pki/", **base)


def ids(issuers=(), mounts=None):
    mounts = [healthy_mount()] if mounts is None else mounts
    return sorted(f.rule_id for f in vp.check_pki(vp.PkiData(mounts=list(mounts), issuers=list(issuers)), NOW))


@pytest.mark.parametrize(
    ("days_left", "expected"), [(-1, ["VP-PKI-001"]), (0, ["VP-PKI-001"]), (5, ["VP-PKI-002"]), (29, ["VP-PKI-002"]), (30, ["VP-PKI-003"]), (89, ["VP-PKI-003"]), (90, []), (400, [])]
)
def test_expiry_windows(days_left, expected):
    assert ids([issuer(cert_facts(days_left))]) == expected


def test_expiry_windows_are_configurable():
    data = vp.PkiData(mounts=[healthy_mount()], issuers=[issuer(cert_facts(100))])
    assert [f.rule_id for f in vp.check_pki(data, NOW, critical_days=7, warning_days=120)] == ["VP-PKI-003"]


def test_revoked_issuer_expiry_is_not_judged():
    assert ids([issuer(cert_facts(-10), revoked=True)]) == []


@pytest.mark.parametrize(
    ("facts", "weakness"),
    [
        (cert_facts(key_bits=1024), "rsa 1024-bit key"),
        (cert_facts(key_type="ec", key_bits=224), "ec 224-bit key"),
        (cert_facts(signature_hash="sha1"), "sha1 signature"),
    ],
)
def test_weak_keys_fire_007(facts, weakness):
    found = vp.check_pki(vp.PkiData(mounts=[healthy_mount()], issuers=[issuer(facts)]), NOW)
    assert [f.rule_id for f in found] == ["VP-PKI-007"]
    assert found[0].evidence["weaknesses"] == [weakness]


def test_strong_ec_and_ed25519_are_quiet():
    assert ids([issuer(cert_facts(key_type="ec", key_bits=256))]) == []
    assert ids([issuer(cert_facts(key_type="ed25519", key_bits=None))]) == []


def test_missing_aia_fires_005_unless_the_mount_sets_it():
    no_aia = issuer(cert_facts(), issuing_certificates=[])
    assert ids([no_aia]) == ["VP-PKI-005"]
    assert ids([no_aia], [healthy_mount(urls={"issuing_certificates": ["http://ca"]})]) == []
    assert ids([no_aia], [healthy_mount(urls=None)]) == []  # urls unreadable: not judged


def test_leaf_not_after_permit_fires_008():
    assert ids([issuer(cert_facts(), leaf_not_after_behavior="permit")]) == ["VP-PKI-008"]
    assert ids([issuer(cert_facts(), leaf_not_after_behavior="truncate")]) == []


def test_mount_rules():
    assert ids(mounts=[healthy_mount(auto_tidy={"enabled": False})]) == ["VP-PKI-004"]
    assert ids(mounts=[healthy_mount(crl={"disable": True, "ocsp_disable": True})]) == ["VP-PKI-006"]
    assert ids(mounts=[healthy_mount(crl={"disable": True, "ocsp_disable": False})]) == []
    assert ids(mounts=[healthy_mount(auto_tidy=None, crl=None)]) == []


def test_issuer_without_parsed_certificate_only_gets_config_rules():
    assert ids([issuer(None, leaf_not_after_behavior="permit")]) == ["VP-PKI-008"]


@pytest.mark.parametrize(("key", "key_type", "bits"), [("rsa", "rsa", 2048), ("ec", "ec", 256)])
def test_describe_certificate(key, key_type, bits):
    facts = vp.describe_certificate(make_pem("Unit CA", days_left=42, key=key))
    assert facts["common_name"] == "Unit CA"
    assert facts["key_type"] == key_type and facts["key_bits"] == bits
    assert facts["signature_hash"] == "sha256"
    assert facts["self_signed"] is True
    assert (vp.parse_time(facts["not_after"]) - NOW).days == 42


def test_describe_certificate_rejects_garbage():
    assert vp.describe_certificate("not a pem") is None
    assert vp.describe_certificate("") is None
