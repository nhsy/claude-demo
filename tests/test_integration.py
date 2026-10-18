"""Live tests against a dev server seeded by scripts/seed_findings.sh, with a token holding
vault-posture-readonly and vault-posture-pki-reader (scripts/posture_token.sh).

task up && task seed && task token && task test:integration      (or: task test:e2e)
"""

import json
import os

import hvac
import pytest
import vault_posture as vp
from hvac import exceptions as hvac_exc

pytestmark = pytest.mark.integration

SEEDED_RULES = {
    "VP-QUOTA-003",
    "VP-QUOTA-004",
    "VP-SEC-001",
    "VP-SEC-002",
    "VP-SEC-004",
    "VP-PLUG-001",
    "VP-PLUG-002",
    *(f"VP-ROLE-00{i}" for i in range(1, 10)),
    *(f"VP-AWS-00{i}" for i in range(1, 5)),
    *(f"VP-GCP-00{i}" for i in range(1, 5)),
    *(f"VP-AZURE-00{i}" for i in range(1, 4)),
    "VP-CERT-001",
    "VP-CERT-002",
    "VP-PKI-002",
    "VP-PKI-003",
    "VP-PKI-004",
    "VP-PKI-005",
    "VP-PKI-006",
    "VP-PKI-008",
}
# Seeded controls that must stay quiet: (rule, object path).
SEEDED_CONTROLS = [
    ("VP-ROLE-006", "auth/kubernetes/role/scoped"),
    ("VP-ROLE-002", "auth/jwt/role/break-glass"),
    ("VP-AWS-001", "auth/aws/role/scoped"),
    ("VP-AWS-002", "auth/aws/role/ec2-migrating"),
    ("VP-GCP-001", "auth/gcp/role/long-jwt"),
    ("VP-GCP-003", "auth/gcp/role/long-jwt"),
    ("VP-GCP-002", "auth/gcp/role/gce-pinned"),
    ("VP-AZURE-001", "auth/azure/role/sub-scoped"),
    ("VP-AZURE-001", "auth/azure/role/pinned"),
    ("VP-AZURE-002", "auth/azure/role/pinned"),
    ("VP-AZURE-003", "auth/azure/role/pinned"),
    ("VP-CERT-001", "auth/cert/certs/scoped"),
    ("VP-CERT-002", "auth/cert/certs/scoped"),
]


@pytest.fixture(scope="module")
def live():
    if not (os.getenv("VAULT_ADDR") and os.getenv("VAULT_TOKEN")):
        pytest.skip("VAULT_ADDR and VAULT_TOKEN (vault-posture-readonly) must be set")
    return hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])


@pytest.fixture(scope="module")
def posture(live, tmp_path_factory):
    out = tmp_path_factory.mktemp("posture")
    assert vp.main(["audit", "--output-dir", str(out)]) == vp.EXIT_OK
    return json.loads(next(out.glob("*-posture-*.json")).read_text())


def test_token_is_the_readonly_policy(live):
    policies = live.auth.token.lookup_self()["data"]["policies"]
    assert policies == ["vault-posture-pki-reader", "vault-posture-readonly"], "run with the token from `task token`, not root"


def test_coverage_is_complete_with_the_readonly_policy(posture):
    assert posture["coverage"]["complete"], posture["coverage"]


def test_seeded_rules_fire(posture):
    fired = set(posture["summary"]["by_rule"])
    assert fired >= SEEDED_RULES
    enterprise = posture["run"]["edition"] == "enterprise"
    assert ("VP-QUOTA-002" in fired) is enterprise
    status = {s["scope"]: s["status"] for s in posture["coverage"]["scopes"]}
    assert status["quotas.lease-count"] == ("absent" if enterprise else "unsupported")


def test_seeded_controls_stay_quiet(posture):
    fired = {(f["rule_id"], f["object"]["path"]) for f in posture["findings"]}
    for control in SEEDED_CONTROLS:
        assert control not in fired


def test_seeded_role_and_pki_details(posture):
    by_path = {(f["rule_id"], f["object"]["path"]) for f in posture["findings"]}
    assert ("VP-ROLE-001", "auth/jwt/role/break-glass") in by_path
    assert ("VP-ROLE-001", "auth/token/roles/ops-root") in by_path
    assert ("VP-ROLE-005", "auth/kubernetes/role/any-pod") in by_path
    assert ("VP-AWS-001", "auth/aws/role/any-principal") in by_path
    assert ("VP-AWS-002", "auth/aws/role/ec2-region-only") in by_path
    assert ("VP-AWS-003", "auth/aws/role/scoped") in by_path
    assert ("VP-AWS-004", "auth/aws/role/ec2-migrating") in by_path
    assert ("VP-GCP-001", "auth/gcp/role/any-sa") in by_path
    assert ("VP-GCP-002", "auth/gcp/role/gce-zone-only") in by_path
    assert ("VP-GCP-003", "auth/gcp/role/project-wide") in by_path
    assert ("VP-GCP-004", "auth/gcp/role/long-jwt") in by_path
    assert ("VP-AZURE-001", "auth/azure/role/any-sp") in by_path
    assert ("VP-AZURE-001", "auth/azure/role/any-sp-eastus") in by_path
    assert ("VP-AZURE-002", "auth/azure/role/loc-only") in by_path
    assert ("VP-AZURE-003", "auth/azure/role/rg-any-group") in by_path
    assert ("VP-CERT-001", "auth/cert/certs/any-cert") in by_path
    assert ("VP-CERT-002", "auth/cert/certs/wild") in by_path
    assert ("VP-PKI-006", "pki_off/") in by_path
    # Two-segment mounts are read with the read-only token too.
    assert ("VP-ROLE-005", "auth/k8s/prod/role/any-pod") in by_path
    nested = [f for f in posture["findings"] if f["rule_id"] == "VP-PKI-003" and f["object"]["path"].startswith("ca/int/issuer/")]
    assert [f["evidence"]["issuer_name"] for f in nested] == ["nested"]
    expiring = next(f for f in posture["findings"] if f["rule_id"] == "VP-PKI-002")
    assert expiring["evidence"]["issuer_name"] == "critical"
    assert "BEGIN CERTIFICATE" not in json.dumps(posture)


def test_seeded_plugin_and_quota_details(posture):
    plugin = next(f for f in posture["findings"] if f["rule_id"] == "VP-PLUG-001")
    assert plugin["object"]["path"] == "secret/posture-dummy"
    scoped = next(f for f in posture["findings"] if f["rule_id"] == "VP-QUOTA-003")
    assert scoped["evidence"]["paths"] == ["auth/userpass/"]


def test_no_seal_operation_secrets_in_output(posture):
    for key in ("generate_root", "rekey"):
        assert set(posture["data"]["security"][key]) <= set(vp.ATTEMPT_FIELDS)
    assert "nonce" not in json.dumps(posture)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/v1/sys/quotas/rate-limit/x", {"rate": 1}),
        ("delete", "/v1/sys/generate-root/attempt", None),
        ("post", "/v1/sys/rotate", None),
        ("post", "/v1/sys/policies/acl/x", {"policy": 'path "*" { capabilities = ["sudo"] }'}),
        ("post", "/v1/auth/token/create", {}),
    ],
)
def test_readonly_token_cannot_write(live, method, path, body):
    with pytest.raises(hvac_exc.Forbidden):
        getattr(live.adapter, method)(path, json=body)


# --------------------------------------------------------------------------- access vs Vault


@pytest.fixture(scope="module")
def root_client(live):
    client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.getenv("VAULT_DEV_ROOT_TOKEN", "root"))
    if not client.is_authenticated():
        pytest.skip("dev root token not available (VAULT_DEV_ROOT_TOKEN)")
    return client


def test_access_matches_vault_capabilities(root_client):
    """The offline evaluator agrees with sys/capabilities for a token holding the fixture policies."""
    from conftest import FIXTURE_POLICIES
    from test_access import EXPECTED

    names = []
    for file in sorted(FIXTURE_POLICIES.iterdir()):
        name = f"posture-fixture-{file.stem}"
        root_client.sys.create_or_update_policy(name, file.read_text())
        names.append(name)
    token = root_client.auth.token.create(policies=names, no_default_policy=True, ttl="5m")["auth"]["client_token"]
    rules, _, _ = vp.load_policies([str(FIXTURE_POLICIES)])
    for path in EXPECTED:
        vault_caps = sorted(root_client.adapter.post("/v1/sys/capabilities", json={"token": token, "path": path})["capabilities"])
        assert vp.effective_capabilities(rules, path)["capabilities"] == vault_caps, path
