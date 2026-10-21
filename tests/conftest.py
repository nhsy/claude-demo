import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests
import vault_posture as vp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from hvac import exceptions as hvac_exc

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "skills/vault-posture/schemas"
POLICY_DIR = ROOT / "skills/vault-posture/policies"
FIXTURE_POLICIES = Path(__file__).resolve().parent / "fixtures/policies"
FAKE_TOKEN = "hvs.FAKE-TOKEN-must-never-appear"
# Values Vault returns that must never reach a file: seal-operation nonces/OTPs/encoded tokens,
# and anything outside a role's allowlist.
SECRET_MARKERS = ("NONCE-must-never-appear", "ENCODED-must-never-appear", "OTP-must-never-appear", "ROLE-ID-must-never-appear")
NOW = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture
def schema():
    return json.loads((SCHEMA_DIR / "findings.schema.json").read_text())


@pytest.fixture
def access_schema():
    return json.loads((SCHEMA_DIR / "access.schema.json").read_text())


@pytest.fixture
def diff_schema():
    return json.loads((SCHEMA_DIR / "diff.schema.json").read_text())


def not_found(message=""):
    return hvac_exc.InvalidPath(message or None, errors=[message] if message else [])


def enterprise_only():
    return not_found("enterprise-only feature")


def unsupported_path():
    return not_found("1 error occurred:\n\t* unsupported path\n\n")


def ok(data):
    return {"request_id": "r", "data": data}


def make_pem(common_name="Test CA", days_left=10, key="rsa", now=NOW):
    """A self-signed CA certificate expiring `days_left` days after `now`."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048) if key == "rsa" else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=days_left))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


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


def mounts(**types):
    return ok({f"{path}/": {"type": mtype, "config": {}} for path, mtype in types.items()})


# Dated from the real clock: the CLI judges expiry against the time it runs.
CA_PEM = make_pem("Fixture CA", days_left=10, now=datetime.now(UTC))

# Routes keyed by (path, is_list) in the root namespace. A Community server with one path-scoped
# rate-limit quota, a root generation and a rekey in progress, an old barrier key, one unversioned
# external plugin, an audience-only JWT role, a wildcard Kubernetes role and a PKI mount whose
# only issuer expires in 10 days with auto-tidy off.
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
    ("sys/audit", False): ok({"file/": {"type": "file", "description": "", "local": False, "path": "file/", "options": {"file_path": "/var/log/vault/audit.log", "hmac_accessor": "true"}}}),
    ("sys/config/state/sanitized", False): ok(
        {
            "max_lease_ttl": 0,
            "default_lease_ttl": 0,
            "listeners": [{"type": "tcp", "config": {"address": "127.0.0.1:8200", "tls_disable": True, "proxy_protocol_behavior": "allow_authorized"}}],
            "telemetry": {"circonus_api_token": SECRET_MARKERS[0]},
            "storage": {"type": "raft", "path": "/vault/data"},
            "seals": [{"type": "shamir"}],
        }
    ),
    ("sys/namespaces", True): enterprise_only(),
    ("sys/auth", False): mounts(token="token", jwt="jwt", kubernetes="kubernetes", userpass="userpass"),
    ("auth/token/roles", True): not_found(),
    ("auth/jwt/role", True): ok({"keys": ["ci"]}),
    ("auth/jwt/role/ci", False): ok(
        {"role_type": "jwt", "bound_audiences": ["https://github.com/acme"], "bound_subject": "", "bound_claims": None, "token_policies": ["deploy"], "role_id": SECRET_MARKERS[3]}
    ),
    ("auth/kubernetes/role", True): ok({"keys": ["any"]}),
    ("auth/kubernetes/role/any", False): ok({"bound_service_account_names": ["*"], "bound_service_account_namespaces": ["*"], "token_policies": ["app"]}),
    ("sys/mounts", False): mounts(secret="kv", pki="pki", sys="system"),
    ("pki/config/auto-tidy", False): ok({"enabled": False, "interval_duration": 43200}),
    ("pki/config/crl", False): ok({"disable": False, "ocsp_disable": False, "auto_rebuild": False}),
    ("pki/config/urls", False): ok({"issuing_certificates": ["http://vault.test/v1/pki/ca"], "crl_distribution_points": [], "ocsp_servers": []}),
    ("pki/issuers", True): ok({"keys": ["id-1"], "key_info": {"id-1": {"issuer_name": "root", "is_default": True}}}),
    ("pki/issuer/id-1", False): ok(
        {"issuer_id": "id-1", "issuer_name": "root", "certificate": CA_PEM, "ca_chain": [CA_PEM], "leaf_not_after_behavior": "err", "issuing_certificates": [], "revoked": False}
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


def route(routes, namespace, path, is_list):
    """Namespaced routes are keyed (namespace, path, is_list); root ones (path, is_list)."""
    key = (namespace, path, is_list) if namespace else (path, is_list)
    return routes.get(key, not_found())


class FakeReader:
    """Stands in for vp.Reader: routes paths to canned responses or exceptions and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, path, params=None, namespace=""):
        is_list = bool(params and params.get("list"))
        self.calls.append((namespace, path, is_list))
        value = route(self.routes, namespace, path, is_list)
        if isinstance(value, Exception):
            raise value
        return value

    data = vp.Reader.data
    list = vp.Reader.list
    list_info = vp.Reader.list_info


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

    `.sent` holds (method, namespace, path, params) per request; tests may edit `.routes` before running.
    """
    vault = FakeVault(routes=dict(COMMUNITY_ROUTES))

    def request(self, method, url, **kwargs):
        path = url.split("/v1/", 1)[1]
        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}
        namespace = (headers.get("X-Vault-Namespace") or "").strip("/")
        vault.sent.append((method.upper(), namespace, path, dict(params)))
        assert headers.get("X-Vault-Token") == FAKE_TOKEN or path == "sys/health"
        if path == "sys/health":
            return fake_response(200, HEALTH)
        value = route(vault.routes, namespace, path, bool(params.get("list")))
        if isinstance(value, Exception):
            status = {hvac_exc.InvalidPath: 404, hvac_exc.Forbidden: 403, hvac_exc.InvalidRequest: 400}.get(type(value), 500)
            return fake_response(status, {"errors": value.errors or []})
        return fake_response(200, value)

    monkeypatch.setattr(requests.Session, "request", request)
    monkeypatch.setenv("VAULT_ADDR", "http://vault.test:8200")
    monkeypatch.setenv("VAULT_TOKEN", FAKE_TOKEN)
    monkeypatch.delenv("VAULT_POSTURE_OUTPUT_DIR", raising=False)
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)
    return vault
