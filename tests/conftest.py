import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
import requests
import vault_posture as vp
from hvac import exceptions as hvac_exc

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "skills/vault-posture/schemas/findings.schema.json"
POLICY_PATH = ROOT / "skills/vault-posture/policies/vault-posture-readonly.hcl"
FAKE_TOKEN = "hvs.FAKE-TOKEN-must-never-appear"
# Values the generate-root/rekey status endpoints return that must never reach a file.
SECRET_MARKERS = ("NONCE-must-never-appear", "ENCODED-must-never-appear", "OTP-must-never-appear")
NOW = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def not_found(message=""):
    return hvac_exc.InvalidPath(message or None, errors=[message] if message else [])


def enterprise_only():
    return not_found("enterprise-only feature")


def unsupported_path():
    return not_found("1 error occurred:\n\t* unsupported path\n\n")


def ok(data):
    return {"request_id": "r", "data": data}


def attempt_body(started=False):
    return {
        "started": started,
        "progress": 1 if started else 0,
        "required": 3,
        "nonce": SECRET_MARKERS[0],
        "encoded_token": SECRET_MARKERS[1],
        "otp": SECRET_MARKERS[2],
        "otp_length": 28,
    }


def plugin(name, ptype="secret", version="v1.0.0+builtin", builtin=True):
    return {"name": name, "type": ptype, "version": version, "builtin": builtin, "deprecation_status": "supported"}


# Routes keyed by (path, is_list). A Community server with one path-scoped rate-limit quota,
# a root generation and a rekey in progress, an old barrier key and one unversioned external plugin.
COMMUNITY_ROUTES = {
    ("auth/token/lookup-self", False): ok({"policies": ["vault-posture-readonly"]}),
    ("sys/quotas/config", False): ok({"enable_rate_limit_audit_logging": False, "enable_rate_limit_response_headers": False, "rate_limit_exempt_paths": ["sys/health"]}),
    ("sys/quotas/rate-limit", True): ok({"keys": ["login"]}),
    ("sys/quotas/rate-limit/login", False): ok({"name": "login", "type": "rate-limit", "path": "auth/userpass/", "rate": 10, "interval": 1, "block_interval": 0, "role": "", "inheritable": False}),
    ("sys/quotas/lease-count", True): enterprise_only(),
    ("sys/generate-root/attempt", False): attempt_body(started=True),
    ("sys/generate-recovery-token/attempt", False): unsupported_path(),
    ("sys/rekey/init", False): attempt_body(started=True),
    ("sys/rekey-recovery-key/init", False): hvac_exc.InvalidRequest(errors=["recovery rekeying not supported"]),
    ("sys/key-status", False): {"term": 1, "install_time": "2024-01-02T03:04:05.123456789Z", "encryptions": 42},
    ("sys/rotate/config", False): ok({"enabled": True, "interval": 0, "max_operations": 3865470566}),
    ("sys/plugins/catalog", False): ok(
        {
            "auth": ["approle"],
            "detailed": [plugin("approle", "auth"), plugin("kv"), plugin("custom-db", "database", version="", builtin=False)],
        }
    ),
}

HEALTH = {
    "initialized": True,
    "sealed": False,
    "standby": False,
    "replication_dr_mode": "disabled",
    "version": "2.1.1",
    "cluster_name": "vault-cluster-test",
}


class FakeReader:
    """Stands in for vp.Reader: routes paths to canned responses or exceptions and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, path, params=None):
        is_list = bool(params and params.get("list"))
        self.calls.append((path, is_list))
        value = self.routes.get((path, is_list), not_found())
        if isinstance(value, Exception):
            raise value
        return value

    data = vp.Reader.data
    list = vp.Reader.list


@pytest.fixture
def community_reader():
    return FakeReader(dict(COMMUNITY_ROUTES))


def fake_response(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    return response


@dataclass
class FakeVault:
    routes: dict
    sent: list = field(default_factory=list)


@pytest.fixture
def fake_vault(monkeypatch):
    """Patch requests at the session level: every HTTP request the script sends is recorded.

    `.sent` holds (method, path, params) per request; tests may edit `.routes` before running.
    """
    vault = FakeVault(routes=dict(COMMUNITY_ROUTES))

    def request(self, method, url, **kwargs):
        path = url.split("/v1/", 1)[1]
        params = kwargs.get("params") or {}
        vault.sent.append((method.upper(), path, dict(params)))
        assert kwargs.get("headers", {}).get("X-Vault-Token") == FAKE_TOKEN or path == "sys/health"
        if path == "sys/health":
            return fake_response(200, HEALTH)
        value = vault.routes.get((path, bool(params.get("list"))), not_found())
        if isinstance(value, Exception):
            status = {hvac_exc.InvalidPath: 404, hvac_exc.Forbidden: 403, hvac_exc.InvalidRequest: 400}.get(type(value), 500)
            return fake_response(status, {"errors": value.errors or []})
        return fake_response(200, value)

    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setenv("VAULT_ADDR", "http://vault.test:8200")
    monkeypatch.setenv("VAULT_TOKEN", FAKE_TOKEN)
    monkeypatch.delenv("VAULT_POSTURE_OUTPUT_DIR", raising=False)
    return vault
