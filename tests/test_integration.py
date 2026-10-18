"""Live tests against a dev server seeded by scripts/seed_findings.sh, with a vault-posture-readonly token.

task up && task seed && task token && task test:integration      (or: task test:e2e)
"""

import json
import os

import hvac
import pytest
import vault_posture as vp
from hvac import exceptions as hvac_exc

pytestmark = pytest.mark.integration

SEEDED_RULES = {"VP-QUOTA-003", "VP-QUOTA-004", "VP-SEC-001", "VP-SEC-002", "VP-SEC-004", "VP-PLUG-001", "VP-PLUG-002"}


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
    assert policies == ["vault-posture-readonly"], "run with the token from `task token`, not root"


def test_coverage_is_complete_with_the_readonly_policy(posture):
    assert posture["coverage"]["complete"], posture["coverage"]


def test_seeded_rules_fire(posture):
    fired = set(posture["summary"]["by_rule"])
    assert fired >= SEEDED_RULES
    enterprise = posture["run"]["edition"] == "enterprise"
    assert ("VP-QUOTA-002" in fired) is enterprise
    status = {s["scope"]: s["status"] for s in posture["coverage"]["scopes"]}
    assert status["quotas.lease-count"] == ("absent" if enterprise else "unsupported")


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
