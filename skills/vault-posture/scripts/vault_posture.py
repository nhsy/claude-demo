#!/usr/bin/env python3
"""Read-only HashiCorp Vault security posture collector for the vault-posture Claude skill.

Subcommands write small JSON files (mode 0600) and print only the written paths on
stdout; diagnostics go to stderr. Every request is an HTTP GET (lists use ?list=true):
nothing here writes to Vault.

  audit     every live check below                  -> {cluster}-posture-{ts}.json
  quotas    rate-limit and lease-count quotas        -> {cluster}-quotas-{ts}.json
  security  root/recovery token generation, rekey,  -> {cluster}-security-{ts}.json
            barrier key age and rotation, plugin catalog
  roles     JWT/OIDC, Kubernetes, AppRole and token -> {cluster}-roles-{ts}.json
            role bindings, per namespace
  pki       PKI issuer expiry, key strength, CRL/    -> {cluster}-pki-{ts}.json
            OCSP/AIA, auto-tidy, per namespace (needs the vault-posture-pki-reader add-on)
  access    offline: effective capabilities of ACL  -> access-{ts}.json
            policy files on a path (no Vault access)
  diff      offline: compare two findings documents -> {cluster}-diff-{ts}.json
            by fingerprint (no Vault access)

Complements the vault-ops skill (health, inventory, policies, usage): rule IDs are VP-*.
"""

# /// script
# requires-python = ">=3.12"
# dependencies = ["hvac==2.4.0", "requests>=2.32,<3", "cryptography==50.0.2"]
#
# [tool.uv]
# exclude-newer = "2026-10-05T00:00:00Z"
# exclude-newer-package = { certifi = "2026-10-21T00:00:00Z" }
# ///

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

import hvac
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from hvac import exceptions as hvac_exc

TOOL_NAME = "vault-posture"
TOOL_VERSION = "0.2.0"
SCHEMA_VERSION = "1.1.0"

EXIT_OK, EXIT_FATAL, EXIT_GAPS, EXIT_FINDINGS, EXIT_INTERRUPTED = 0, 1, 2, 3, 130

# Relative to the working directory (the user's project), so Claude can read results without
# leaving it. A directory the script creates gets a catch-all .gitignore: results are never committed.
DEFAULT_OUTPUT_DIR = ".tmp/vault-posture"

# VP-SEC-003: barrier key age that warrants a rotation review.
KEY_AGE_WARNING_DAYS = 365
# VP-PKI-002/003: issuer expiry windows.
PKI_CRITICAL_DAYS = 30
PKI_WARNING_DAYS = 90
# VP-PKI-007: weakest acceptable issuer keys.
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
# The read-only policies cover the root namespace plus this many nesting levels.
MAX_NAMESPACE_DEPTH = 5

# 404 bodies for an Enterprise-only path on Community: "enterprise-only feature" (2.x).
ENTERPRISE_ONLY_MARKERS = ("enterprise-only feature",)
# Endpoints that only exist for some seal types answer 404 "unsupported path" or 400 "... not supported".
NOT_APPLICABLE_MARKERS = ("unsupported path", "not supported")

# sys/health query that returns 200 (and a body) for every node state.
HEALTH_PARAMS = {
    "standbyok": "true",
    "perfstandbyok": "true",
    "sealedcode": "200",
    "uninitcode": "200",
    "drsecondarycode": "200",
    "performancestandbycode": "200",
    "standbycode": "200",
}

# Fields kept from each endpoint. Everything else is dropped before it reaches a file: the
# generate-root and rekey status bodies carry nonces, OTP lengths and encoded tokens.
QUOTA_FIELDS = ("name", "type", "path", "role", "rate", "interval", "block_interval", "max_leases", "inheritable", "group_by")
QUOTA_CONFIG_FIELDS = ("enable_rate_limit_audit_logging", "enable_rate_limit_response_headers")
ATTEMPT_FIELDS = ("started", "progress", "required")
KEY_STATUS_FIELDS = ("term", "install_time", "encryptions")
ROTATE_FIELDS = ("enabled", "interval", "max_operations")
PLUGIN_FIELDS = ("name", "type", "version", "builtin", "deprecation_status")
TOKEN_PARAM_FIELDS = (
    "token_policies",
    "token_ttl",
    "token_max_ttl",
    "token_explicit_max_ttl",
    "token_period",
    "token_type",
    "token_bound_cidrs",
    "token_num_uses",
    "token_no_default_policy",
)
# Auth method type -> (role list path under the mount, fields kept). Role IDs, secret IDs and
# their accessors live under other endpoints and are never read.
ROLE_SOURCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "jwt": (
        "role",
        (
            "role_type",
            "bound_audiences",
            "bound_subject",
            "bound_claims",
            "bound_claims_type",
            "user_claim",
            "groups_claim",
            "allowed_redirect_uris",
            "verbose_oidc_logging",
            *TOKEN_PARAM_FIELDS,
        ),
    ),
    "kubernetes": (
        "role",
        ("bound_service_account_names", "bound_service_account_namespaces", "bound_service_account_namespace_selector", "audience", "alias_name_source", *TOKEN_PARAM_FIELDS),
    ),
    "aws": (
        "role",
        (
            "auth_type",
            "bound_iam_principal_arn",
            "bound_account_id",
            "bound_iam_role_arn",
            "bound_iam_instance_profile_arn",
            "bound_ec2_instance_id",
            "bound_ami_id",
            "bound_vpc_id",
            "bound_subnet_id",
            "bound_region",
            "inferred_entity_type",
            "resolve_aws_unique_ids",
            "allow_instance_migration",
            "disallow_reauthentication",
            *TOKEN_PARAM_FIELDS,
        ),
    ),
    "gcp": (
        "role",
        (
            "type",
            "bound_service_accounts",
            "bound_projects",
            "bound_zones",
            "bound_regions",
            "bound_instance_groups",
            "bound_labels",
            "max_jwt_exp",
            "allow_gce_inference",
            "add_group_aliases",
            *TOKEN_PARAM_FIELDS,
        ),
    ),
    "azure": (
        "role",
        (
            "bound_service_principal_ids",
            "bound_group_ids",
            "bound_subscription_ids",
            "bound_resource_groups",
            "bound_locations",
            "bound_scale_sets",
            *TOKEN_PARAM_FIELDS,
        ),
    ),
    # The role's trusted CA (`certificate`) is never kept.
    "cert": (
        "certs",
        (
            "allowed_names",
            "allowed_common_names",
            "allowed_dns_sans",
            "allowed_email_sans",
            "allowed_uri_sans",
            "allowed_organizational_units",
            "allowed_organizations",
            "required_extensions",
            "ocsp_enabled",
            *TOKEN_PARAM_FIELDS,
        ),
    ),
    "approle": ("role", ("bind_secret_id", "secret_id_bound_cidrs", "secret_id_num_uses", "secret_id_ttl", "local_secret_ids", *TOKEN_PARAM_FIELDS)),
    "token": (
        "roles",
        (
            "allowed_policies",
            "allowed_policies_glob",
            "disallowed_policies",
            "orphan",
            "renewable",
            "period",
            "explicit_max_ttl",
            "token_period",
            "token_explicit_max_ttl",
            "token_type",
            "path_suffix",
        ),
    ),
}
# Mount types sharing a role source (Enterprise child namespaces report ns_token).
ROLE_SOURCE_ALIASES = {"oidc": "jwt", "ns_token": "token"}
ISSUER_FIELDS = ("issuer_name", "leaf_not_after_behavior", "issuing_certificates", "crl_distribution_points", "ocsp_servers", "usage", "revoked")
AUTO_TIDY_FIELDS = ("enabled", "interval_duration", "tidy_cert_store", "tidy_revoked_certs", "tidy_expired_issuers")
CRL_FIELDS = ("disable", "ocsp_disable", "auto_rebuild", "enable_delta", "expiry")
URL_FIELDS = ("issuing_certificates", "crl_distribution_points", "ocsp_servers", "enable_templating")

SEVERITIES = ("high", "medium", "low", "info")


@dataclass(frozen=True)
class Rule:
    severity: str
    category: str
    title: str


RULES: dict[str, Rule] = {
    "VP-QUOTA-001": Rule("medium", "quotas", "No rate-limit quota is defined"),
    "VP-QUOTA-002": Rule("medium", "quotas", "No lease-count quota is defined"),
    "VP-QUOTA-003": Rule("low", "quotas", "Quotas exist but none applies to the whole cluster"),
    "VP-QUOTA-004": Rule("info", "quotas", "Requests rejected by rate-limit quotas are not audit-logged"),
    "VP-SEC-001": Rule("high", "security", "A root or recovery token generation is in progress"),
    "VP-SEC-002": Rule("medium", "security", "A rekey of the unseal or recovery keys is in progress"),
    "VP-SEC-003": Rule("low", "security", "Barrier encryption key is older than the review threshold"),
    "VP-SEC-004": Rule("info", "security", "Time-based automatic barrier key rotation is disabled"),
    "VP-PLUG-001": Rule("low", "plugins", "External plugin is registered without a version"),
    "VP-PLUG-002": Rule("info", "plugins", "External (non-builtin) plugins are registered"),
    "VP-ROLE-001": Rule("high", "roles", "Role can issue tokens with the root policy"),
    "VP-ROLE-002": Rule("medium", "roles", "JWT role is bound only by audience"),
    "VP-ROLE-003": Rule("medium", "roles", "JWT/OIDC role binds claims with a wildcard"),
    "VP-ROLE-004": Rule("low", "roles", "OIDC role logs tokens and claims verbosely"),
    "VP-ROLE-005": Rule("high", "roles", "Kubernetes role accepts any service account in any namespace"),
    "VP-ROLE-006": Rule("medium", "roles", "Kubernetes role accepts any service account name or any namespace"),
    "VP-ROLE-007": Rule("medium", "roles", "AppRole role does not require a secret ID"),
    "VP-ROLE-008": Rule("low", "roles", "AppRole secret IDs never expire"),
    "VP-ROLE-009": Rule("low", "roles", "Role issues periodic tokens with no explicit max TTL"),
    "VP-AWS-001": Rule("high", "roles", "AWS IAM role accepts a principal in any AWS account"),
    "VP-AWS-002": Rule("high", "roles", "AWS EC2 role is not bound to an account or instance"),
    "VP-AWS-003": Rule("low", "roles", "AWS IAM role matches principals by name, not unique ID"),
    "VP-AWS-004": Rule("low", "roles", "AWS EC2 role allows instance migration"),
    "VP-GCP-001": Rule("high", "roles", "GCP IAM role accepts any service account in any project"),
    "VP-GCP-002": Rule("high", "roles", "GCP GCE role is not bound to a project or service account"),
    "VP-GCP-003": Rule("medium", "roles", "GCP IAM role accepts every service account in its projects"),
    "VP-GCP-004": Rule("low", "roles", "GCP IAM role accepts signed JWTs valid longer than 15 minutes"),
    "VP-AZURE-001": Rule("medium", "roles", "Azure role accepts any identity in the tenant"),
    "VP-AZURE-002": Rule("low", "roles", "Azure role binds no specific service principal or group"),
    "VP-AZURE-003": Rule("low", "roles", "Azure role binds a resource group or scale set in any subscription"),
    "VP-CERT-001": Rule("medium", "roles", "Cert auth role accepts any certificate its CA signed"),
    "VP-CERT-002": Rule("medium", "roles", "Cert auth role matches names with a catch-all wildcard"),
    "VP-PKI-001": Rule("high", "pki", "PKI issuer certificate has expired"),
    "VP-PKI-002": Rule("medium", "pki", "PKI issuer certificate expires within the critical window"),
    "VP-PKI-003": Rule("low", "pki", "PKI issuer certificate expires within the warning window"),
    "VP-PKI-004": Rule("low", "pki", "PKI mount has automatic tidy disabled"),
    "VP-PKI-005": Rule("low", "pki", "PKI issuer has no AIA issuing-certificates URL"),
    "VP-PKI-006": Rule("medium", "pki", "PKI mount has both CRL and OCSP disabled"),
    "VP-PKI-007": Rule("medium", "pki", "PKI issuer uses a weak key or signature algorithm"),
    "VP-PKI-008": Rule("low", "pki", "PKI issuer lets leaf certificates outlive it"),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    namespace: str  # "" for root, "a/b" for children
    object_kind: str
    object_path: str | None
    detail: str
    evidence: MappingProxyType = field(default_factory=lambda: MappingProxyType({}), compare=False, hash=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.namespace}|{self.object_kind}|{self.object_path or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "title": self.rule.title,
            "namespace": display_namespace(self.namespace),
            "object": {"kind": self.object_kind, "path": self.object_path},
            "detail": self.detail,
            "evidence": dict(sorted(self.evidence.items())),
        }


def finding(rule_id: str, object_kind: str, object_path: str | None, detail: str, namespace: str = "", **evidence: Any) -> Finding:
    return Finding(rule_id, namespace, object_kind, object_path, detail, MappingProxyType(evidence))


# --------------------------------------------------------------------------- helpers


def pick(source: dict[str, Any] | None, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: source[k] for k in fields if source and k in source}


def display_namespace(path: str) -> str:
    return "/" if path in ("", "/") else f"{path.strip('/')}/"


def normalise_namespace(path: str | None) -> str:
    return (path or "").strip().strip("/")


def join_namespace(parent: str, child: str) -> str:
    return "/".join(p for p in (parent, child.strip("/")) if p)


def parse_time(timestamp: Any) -> datetime | None:
    if not isinstance(timestamp, str) or not timestamp:
        return None
    # Vault writes nanoseconds; fromisoformat takes at most microseconds.
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", timestamp).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(trimmed)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, list | tuple) else [value]


def sanitise_error(exc: BaseException) -> str:
    """Exception class plus HTTP status only: hvac messages can echo request URLs."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    message = type(exc).__name__ + (f" (HTTP {status})" if status else "")
    return message[:200]


def error_text(exc: BaseException) -> str:
    return " ".join(str(e) for e in (getattr(exc, "errors", None) or [str(exc)])).lower()


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------- vault access


@dataclass
class Config:
    addr: str
    token: str
    verify: bool | str
    namespace: str = ""

    @classmethod
    def from_env(cls, namespace: str | None = None) -> Config:
        addr = os.getenv("VAULT_ADDR", "")
        token = os.getenv("VAULT_TOKEN", "")
        if not addr or not token:
            raise SystemExit("error: VAULT_ADDR and VAULT_TOKEN must be set in the environment")
        skip = os.getenv("VAULT_SKIP_VERIFY", "").lower() in ("1", "true")
        verify: bool | str = False if skip else (os.getenv("VAULT_CACERT") or True)
        if verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ns = namespace if namespace is not None else os.getenv("VAULT_NAMESPACE", "")
        return cls(addr=addr.rstrip("/"), token=token, verify=verify, namespace=normalise_namespace(ns))


class Reader:
    """The only route to Vault, and GET-only: lists are GET ?list=true, so no other verb is ever sent."""

    def __init__(self, config: Config):
        self.config = config
        self._session = requests.Session()
        # hvac lets a passed-in session's verify override its own, so TLS settings live on the session.
        self._session.verify = config.verify
        self._clients: dict[str, hvac.Client] = {}

    def _client(self, namespace: str) -> hvac.Client:
        if namespace not in self._clients:
            self._clients[namespace] = hvac.Client(url=self.config.addr, token=self.config.token, namespace=namespace or None, verify=self.config.verify, session=self._session)
        return self._clients[namespace]

    def get(self, path: str, params: dict[str, Any] | None = None, namespace: str = "") -> dict[str, Any]:
        """GET /v1/<path>; raises hvac exceptions (InvalidPath on 404, Forbidden on 403, ...)."""
        response = self._client(namespace).adapter.get(f"/v1/{path}", params=params)
        return response if isinstance(response, dict) else {}

    def data(self, path: str, namespace: str = "") -> dict[str, Any]:
        payload = self.get(path, namespace=namespace)
        return payload["data"] if isinstance(payload.get("data"), dict) else payload

    def list(self, path: str, namespace: str = "") -> list[str]:
        return list(self.get(path, params={"list": "true"}, namespace=namespace).get("data", {}).get("keys") or [])

    def list_info(self, path: str, namespace: str = "") -> dict[str, Any]:
        """A list's key_info (keys -> metadata), falling back to bare keys."""
        data = self.get(path, params={"list": "true"}, namespace=namespace).get("data", {})
        return data.get("key_info") or {k: {} for k in data.get("keys") or []}

    def probe(self) -> dict[str, Any]:
        """Unauthenticated sys/health: cluster name, version and whether the node serves reads."""
        try:
            return self.get("sys/health", params=HEALTH_PARAMS)
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            raise SystemExit(f"error: cannot reach Vault at {self.config.addr}: {sanitise_error(exc)}") from exc

    def validate(self) -> None:
        try:
            self.get("auth/token/lookup-self")
        except hvac_exc.Forbidden as exc:
            raise SystemExit("error: token rejected (403 on auth/token/lookup-self)") from exc
        except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
            raise SystemExit(f"error: token validation failed at {self.config.addr}: {sanitise_error(exc)}") from exc


def connect(namespace: str | None = None) -> tuple[Config, Reader, dict[str, Any]]:
    config = Config.from_env(namespace)
    reader = Reader(config)
    probe = reader.probe()
    if probe.get("initialized") is False:
        raise SystemExit(f"error: {config.addr} is not initialized, so it rejects authenticated reads")
    if probe.get("sealed") is True:
        raise SystemExit(f"error: {config.addr} is sealed, so it rejects authenticated reads")
    if probe.get("replication_dr_mode") == "secondary":
        raise SystemExit(f"error: {config.addr} is a DR secondary, which rejects authenticated reads; run against the primary")
    reader.validate()
    return config, reader, probe


# --------------------------------------------------------------------------- coverage


# Scope statuses. `denied` and `error` make coverage incomplete; the rest are complete answers.
OK, ABSENT, DENIED, UNSUPPORTED, NOT_APPLICABLE, ERROR = "ok", "absent", "denied", "unsupported", "not_applicable", "error"


@dataclass
class Coverage:
    scopes: list[dict[str, str]] = field(default_factory=list)

    def record(self, scope: str, status: str, detail: str | None = None, namespace: str = "") -> None:
        entry = {"namespace": display_namespace(namespace), "scope": scope, "status": status}
        if detail:
            entry["detail"] = detail
        self.scopes.append(entry)

    def status(self, scope: str, namespace: str = "") -> str | None:
        ns = display_namespace(namespace)
        return next((s["status"] for s in self.scopes if s["scope"] == scope and s["namespace"] == ns), None)

    @property
    def complete(self) -> bool:
        return not any(s["status"] in (DENIED, ERROR) for s in self.scopes)

    def to_dict(self) -> dict[str, Any]:
        return {"complete": self.complete, "scopes": sorted(self.scopes, key=lambda s: (s["namespace"], s["scope"]))}


def classify(exc: BaseException) -> str:
    """Map a failed read to a coverage status."""
    if isinstance(exc, hvac_exc.Forbidden):
        return DENIED
    text = error_text(exc)
    if isinstance(exc, hvac_exc.InvalidPath):
        if any(m in text for m in ENTERPRISE_ONLY_MARKERS):
            return UNSUPPORTED
        if any(m in text for m in NOT_APPLICABLE_MARKERS):
            return NOT_APPLICABLE
        return ABSENT  # an empty list or a missing object
    if isinstance(exc, hvac_exc.InvalidRequest) and any(m in text for m in NOT_APPLICABLE_MARKERS):
        return NOT_APPLICABLE
    return ERROR


def attempt(coverage: Coverage, scope: str, call: Any, namespace: str = "") -> tuple[str, Any]:
    """Run one read, record its coverage status and return (status, result or None)."""
    try:
        result = call()
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        status = classify(exc)
        coverage.record(scope, status, sanitise_error(exc) if status == ERROR else None, namespace)
        return status, None
    coverage.record(scope, OK, namespace=namespace)
    return OK, result


def discover_namespaces(reader: Reader, coverage: Coverage, start: str = "") -> list[str]:
    """The start namespace and its descendants, breadth first, up to MAX_NAMESPACE_DEPTH below root."""
    found, queue = [], [start]
    while queue:
        ns = queue.pop(0)
        found.append(ns)
        if ns.count("/") + (1 if ns else 0) >= MAX_NAMESPACE_DEPTH:
            continue
        status, children = attempt(coverage, "namespaces", lambda n=ns: reader.list("sys/namespaces", namespace=n), ns)
        if status == OK:
            queue.extend(join_namespace(ns, child) for child in sorted(children))
    return found


def mounts_of(reader: Reader, coverage: Coverage, kind: str, namespace: str) -> dict[str, str]:
    """{mount path: type} from sys/auth or sys/mounts; built-in metadata keys are dropped."""
    status, body = attempt(coverage, kind, lambda: reader.data(f"sys/{kind}", namespace=namespace), namespace)
    if status != OK:
        return {}
    return {path: info.get("type", "") for path, info in body.items() if isinstance(info, dict) and path.endswith("/")}


# --------------------------------------------------------------------------- quotas


@dataclass
class QuotaData:
    config: dict[str, Any] | None = None
    # None when unreadable or unsupported (see coverage); [] when none are defined.
    rate_limit: list[dict[str, Any]] | None = None
    lease_count: list[dict[str, Any]] | None = None


def _read_quotas(reader: Reader, coverage: Coverage, kind: str) -> list[dict[str, Any]] | None:
    status, names = attempt(coverage, f"quotas.{kind}", lambda: reader.list(f"sys/quotas/{kind}"))
    if status == ABSENT:
        return []
    if status != OK:
        return None
    quotas = []
    for name in names:
        status, body = attempt(coverage, f"quotas.{kind}.{name}", lambda n=name: reader.data(f"sys/quotas/{kind}/{n}"))
        quotas.append(pick(body, QUOTA_FIELDS) if status == OK else {"name": name})
    return quotas


def collect_quotas(reader: Reader, coverage: Coverage) -> QuotaData:
    _, config = attempt(coverage, "quotas.config", lambda: reader.data("sys/quotas/config"))
    return QuotaData(
        config=pick(config, QUOTA_CONFIG_FIELDS) if config is not None else None,
        rate_limit=_read_quotas(reader, coverage, "rate-limit"),
        lease_count=_read_quotas(reader, coverage, "lease-count"),
    )


def check_quotas(data: QuotaData) -> list[Finding]:
    found: list[Finding] = []
    for kind, quotas, rule in (("rate-limit", data.rate_limit, "VP-QUOTA-001"), ("lease-count", data.lease_count, "VP-QUOTA-002")):
        if quotas is None:
            continue  # not judged: unreadable or Enterprise-only on Community
        if not quotas:
            found.append(finding(rule, "quota_type", kind, f"No {kind} quota is defined anywhere in the cluster."))
        elif not any((q.get("path") or "") == "" for q in quotas):
            paths = sorted({q.get("path") or "" for q in quotas})
            found.append(
                finding(
                    "VP-QUOTA-003",
                    "quota_type",
                    kind,
                    f"{len(quotas)} {kind} quota(s) exist, but all are scoped to a path, namespace or role; nothing caps the rest of the cluster.",
                    quota_type=kind,
                    quotas=len(quotas),
                    paths=paths[:10],
                )
            )
    if data.rate_limit and data.config is not None and not data.config.get("enable_rate_limit_audit_logging"):
        found.append(
            finding(
                "VP-QUOTA-004",
                "quota_config",
                "sys/quotas/config",
                "Rate-limit quotas are defined, but requests they reject are not written to the audit log.",
                rate_limit_quotas=len(data.rate_limit),
            )
        )
    return found


# --------------------------------------------------------------------------- security


@dataclass
class SecurityData:
    generate_root: dict[str, Any] | None = None
    generate_recovery_token: dict[str, Any] | None = None
    rekey: dict[str, Any] | None = None
    rekey_recovery: dict[str, Any] | None = None
    key_status: dict[str, Any] | None = None
    rotate_config: dict[str, Any] | None = None
    plugins: list[dict[str, Any]] | None = None


SECURITY_READS = {
    # field: (scope, path, allowlisted fields)
    "generate_root": ("security.generate_root", "sys/generate-root/attempt", ATTEMPT_FIELDS),
    "generate_recovery_token": ("security.generate_recovery_token", "sys/generate-recovery-token/attempt", ATTEMPT_FIELDS),
    "rekey": ("security.rekey", "sys/rekey/init", ATTEMPT_FIELDS),
    "rekey_recovery": ("security.rekey_recovery", "sys/rekey-recovery-key/init", ATTEMPT_FIELDS),
    "key_status": ("security.key_status", "sys/key-status", KEY_STATUS_FIELDS),
    "rotate_config": ("security.rotate_config", "sys/rotate/config", ROTATE_FIELDS),
}


def collect_security(reader: Reader, coverage: Coverage) -> SecurityData:
    data = SecurityData()
    for attr, (scope, path, fields) in SECURITY_READS.items():
        status, body = attempt(coverage, scope, lambda p=path: reader.data(p))
        if status == OK:
            setattr(data, attr, pick(body, fields))
    status, catalog = attempt(coverage, "security.plugin_catalog", lambda: reader.data("sys/plugins/catalog"))
    if status == OK:
        data.plugins = [pick(p, PLUGIN_FIELDS) for p in catalog.get("detailed") or [] if isinstance(p, dict)]
    return data


def check_security(data: SecurityData, now: datetime, key_age_days: int = KEY_AGE_WARNING_DAYS) -> list[Finding]:
    found: list[Finding] = []
    for attr, operation, path in (
        ("generate_root", "root token generation", "sys/generate-root/attempt"),
        ("generate_recovery_token", "recovery token generation", "sys/generate-recovery-token/attempt"),
    ):
        state = getattr(data, attr)
        if state and state.get("started"):
            found.append(
                finding(
                    "VP-SEC-001",
                    "seal_operation",
                    path,
                    f"A {operation} is in progress ({state.get('progress', 0)} of {state.get('required', '?')} key shares provided).",
                    operation=operation,
                    progress=state.get("progress"),
                    required=state.get("required"),
                )
            )
    for attr, operation, path in (("rekey", "unseal key rekey", "sys/rekey/init"), ("rekey_recovery", "recovery key rekey", "sys/rekey-recovery-key/init")):
        state = getattr(data, attr)
        if state and state.get("started"):
            found.append(
                finding(
                    "VP-SEC-002",
                    "seal_operation",
                    path,
                    f"A {operation} is in progress ({state.get('progress', 0)} of {state.get('required', '?')} key shares provided).",
                    operation=operation,
                    progress=state.get("progress"),
                    required=state.get("required"),
                )
            )

    installed = parse_time((data.key_status or {}).get("install_time"))
    if installed is not None:
        age_days = (now - installed).days
        if age_days > key_age_days:
            found.append(
                finding(
                    "VP-SEC-003",
                    "barrier_key",
                    "sys/key-status",
                    f"The barrier key (term {data.key_status.get('term')}) was installed {age_days} days ago, past the {key_age_days}-day review threshold.",
                    term=data.key_status.get("term"),
                    install_time=data.key_status.get("install_time"),
                    age_days=age_days,
                    threshold_days=key_age_days,
                )
            )
    rotate = data.rotate_config
    if rotate is not None and (not rotate.get("enabled") or not rotate.get("interval")):
        found.append(
            finding(
                "VP-SEC-004",
                "barrier_key",
                "sys/rotate/config",
                "Automatic barrier key rotation has no time interval; the key only rotates on the operation-count limit or by hand.",
                enabled=bool(rotate.get("enabled")),
                interval_seconds=rotate.get("interval") or 0,
                max_operations=rotate.get("max_operations"),
            )
        )

    external = [p for p in data.plugins or [] if p.get("builtin") is False]
    for plugin in external:
        if not plugin.get("version"):
            found.append(
                finding(
                    "VP-PLUG-001",
                    "plugin",
                    f"{plugin.get('type')}/{plugin.get('name')}",
                    f"External {plugin.get('type')} plugin '{plugin.get('name')}' is registered without a version, so upgrades and pinning can't be tracked.",
                    plugin_type=plugin.get("type"),
                    plugin_name=plugin.get("name"),
                )
            )
    if external:
        names = sorted(f"{p.get('type')}/{p.get('name')}" for p in external)
        found.append(
            finding(
                "VP-PLUG-002",
                "plugin_catalog",
                "sys/plugins/catalog",
                f"{len(external)} external plugin(s) are registered; each runs third-party code inside Vault's trust boundary.",
                plugins=names[:20],
                count=len(external),
            )
        )
    return found


# --------------------------------------------------------------------------- roles


@dataclass
class AuthRole:
    namespace: str
    mount: str  # "jwt/"
    source: str  # key of ROLE_SOURCES
    name: str
    config: dict[str, Any]

    @property
    def path(self) -> str:
        return f"auth/{self.mount}{ROLE_SOURCES[self.source][0]}/{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {"namespace": display_namespace(self.namespace), "mount": self.mount, "type": self.source, "name": self.name, "config": self.config}


@dataclass
class RoleData:
    namespaces: list[str] = field(default_factory=list)
    roles: list[AuthRole] = field(default_factory=list)


def collect_roles(reader: Reader, coverage: Coverage, namespaces: list[str]) -> RoleData:
    data = RoleData(namespaces=namespaces)
    for ns in namespaces:
        for mount, mount_type in sorted(mounts_of(reader, coverage, "auth", ns).items()):
            source = ROLE_SOURCE_ALIASES.get(mount_type, mount_type)
            if source not in ROLE_SOURCES:
                continue
            segment, fields = ROLE_SOURCES[source]
            base = f"auth/{mount}{segment}"
            status, names = attempt(coverage, f"roles.{mount}", lambda b=base, n=ns: reader.list(b, namespace=n), ns)
            for name in names or []:
                status, body = attempt(coverage, f"roles.{mount}{name}", lambda b=base, r=name, n=ns: reader.data(f"{b}/{r}", namespace=n), ns)
                if status == OK:
                    data.roles.append(AuthRole(ns, mount, source, name, pick(body, fields)))
    return data


def _seconds(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _role_finding(rule_id: str, role: AuthRole, detail: str, **evidence: Any) -> Finding:
    return finding(rule_id, f"{role.source}_role", role.path, detail, namespace=role.namespace, mount=role.mount, role=role.name, **evidence)


def _wildcard_claims(bound_claims: Any) -> dict[str, list[str]]:
    claims = bound_claims if isinstance(bound_claims, dict) else {}
    return {k: [str(v) for v in as_list(vals) if "*" in str(v)] for k, vals in claims.items() if any("*" in str(v) for v in as_list(vals))}


# EC2 bounds that tie a login to one account or instance; bound_region and bound_ami_id don't
# (any account can run an instance in a region, or launch a public AMI).
AWS_EC2_PINNING_BOUNDS = (
    "bound_account_id",
    "bound_iam_role_arn",
    "bound_iam_instance_profile_arn",
    "bound_ec2_instance_id",
    "bound_vpc_id",
    "bound_subnet_id",
)


def _any_account_arn(arn: str) -> bool:
    # arn:<partition>:iam::<account>:<resource>; "*" alone matches every principal.
    parts = arn.split(":")
    return arn == "*" or (len(parts) >= 6 and "*" in parts[4])


# Cert role fields that restrict which certificates (from the role's CA) may log in.
CERT_CONSTRAINTS = (
    "allowed_names",
    "allowed_common_names",
    "allowed_dns_sans",
    "allowed_email_sans",
    "allowed_uri_sans",
    "allowed_organizational_units",
    "allowed_organizations",
    "required_extensions",
)
# Name globs judged by VP-CERT-002 (allowed_names matches the CN or any SAN).
CERT_NAME_GLOBS = ("allowed_names", "allowed_common_names", "allowed_dns_sans")


def _catch_all_name(pattern: str) -> bool:
    # "*", "*.*" and the like, or a wildcard over a bare TLD ("*.com"); "*.example.com" is fine.
    p = pattern.strip()
    return bool(p) and (set(p) <= {"*", "."} or re.fullmatch(r"\*\.[^.*]+\.?", p) is not None)


def check_roles(data: RoleData) -> list[Finding]:
    found: list[Finding] = []
    for role in data.roles:
        c = role.config
        if role.source == "token":
            allowed = [str(p) for p in as_list(c.get("allowed_policies"))]
            globs = [str(p) for p in as_list(c.get("allowed_policies_glob"))]
            if "root" in allowed or any(fnmatch.fnmatchcase("root", g) for g in globs):
                found.append(_role_finding("VP-ROLE-001", role, f"Token role '{role.name}' allows creating tokens with the root policy.", allowed_policies=allowed, allowed_policies_glob=globs))
            period = _seconds(c.get("token_period")) or _seconds(c.get("period"))
            explicit = _seconds(c.get("token_explicit_max_ttl")) or _seconds(c.get("explicit_max_ttl"))
        else:
            policies = [str(p) for p in as_list(c.get("token_policies"))]
            if "root" in policies:
                found.append(_role_finding("VP-ROLE-001", role, f"Logging in through {role.source} role '{role.name}' yields a root token.", token_policies=policies))
            period = _seconds(c.get("token_period"))
            explicit = _seconds(c.get("token_explicit_max_ttl"))
        if period and not explicit:
            found.append(
                _role_finding(
                    "VP-ROLE-009",
                    role,
                    f"Role '{role.name}' issues periodic tokens (period {period}s) with no explicit max TTL, so they can be renewed forever.",
                    period_seconds=period,
                    orphan=bool(c.get("orphan")) if role.source == "token" else None,
                )
            )

        if role.source == "jwt":
            audiences = as_list(c.get("bound_audiences"))
            if c.get("role_type", "oidc") == "jwt" and audiences and not c.get("bound_subject") and not c.get("bound_claims"):
                found.append(
                    _role_finding(
                        "VP-ROLE-002",
                        role,
                        f"JWT role '{role.name}' checks only the audience: any token the issuer mints for that audience can log in.",
                        bound_audiences=audiences,
                    )
                )
            wildcards = _wildcard_claims(c.get("bound_claims"))
            if wildcards and c.get("bound_claims_type") == "glob":
                found.append(_role_finding("VP-ROLE-003", role, f"Role '{role.name}' matches bound claims with wildcards: {', '.join(sorted(wildcards))}.", wildcard_claims=wildcards))
            if c.get("verbose_oidc_logging"):
                found.append(_role_finding("VP-ROLE-004", role, f"Role '{role.name}' writes ID tokens and claims to the server log (verbose_oidc_logging)."))

        if role.source == "kubernetes":
            any_name = "*" in as_list(c.get("bound_service_account_names"))
            any_ns = "*" in as_list(c.get("bound_service_account_namespaces")) and not c.get("bound_service_account_namespace_selector")
            if any_name and any_ns:
                found.append(_role_finding("VP-ROLE-005", role, f"Kubernetes role '{role.name}' accepts every service account in every namespace of the cluster."))
            elif any_name or any_ns:
                scope = "service account name" if any_name else "namespace"
                found.append(_role_finding("VP-ROLE-006", role, f"Kubernetes role '{role.name}' accepts any {scope}.", any_service_account=any_name, any_namespace=any_ns))

        if role.source == "approle":
            if c.get("bind_secret_id") is False:
                found.append(
                    _role_finding(
                        "VP-ROLE-007",
                        role,
                        f"AppRole '{role.name}' logs in with the role ID alone; the role ID becomes a static password.",
                        secret_id_bound_cidrs=as_list(c.get("secret_id_bound_cidrs")),
                        token_bound_cidrs=as_list(c.get("token_bound_cidrs")),
                    )
                )
            elif "secret_id_ttl" in c and not _seconds(c.get("secret_id_ttl")):
                found.append(
                    _role_finding(
                        "VP-ROLE-008",
                        role,
                        f"AppRole '{role.name}' issues secret IDs that never expire.",
                        secret_id_num_uses=c.get("secret_id_num_uses"),
                    )
                )

        if role.source == "aws":
            found.extend(_check_aws_role(role))
        if role.source == "gcp":
            found.extend(_check_gcp_role(role))
        if role.source == "azure":
            found.extend(_check_azure_role(role))
        if role.source == "cert":
            found.extend(_check_cert_role(role))
    return found


def _check_cert_role(role: AuthRole) -> list[Finding]:
    c = role.config
    if not any(as_list(c.get(f)) for f in CERT_CONSTRAINTS):
        return [
            _role_finding(
                "VP-CERT-001",
                role,
                f"Cert role '{role.name}' sets no name, organization or extension constraint: any client certificate its trusted CA signed can log in.",
                ocsp_enabled=c.get("ocsp_enabled"),
            )
        ]
    # Vault ANDs the constraint fields and ORs the values within one, so a field holding a
    # catch-all accepts every name, and the role is wide open only if no other field narrows it.
    broad = {f: [str(p) for p in as_list(c.get(f)) if _catch_all_name(str(p))] for f in CERT_NAME_GLOBS}
    broad = {f: pats for f, pats in broad.items() if pats}
    narrowed = any(as_list(c.get(f)) and f not in broad for f in CERT_CONSTRAINTS)
    if broad and not narrowed:
        shown = ", ".join(f"{f}={p}" for f, pats in broad.items() for p in pats)
        return [
            _role_finding(
                "VP-CERT-002",
                role,
                f"Cert role '{role.name}' matches names with a catch-all wildcard ({shown}): any certificate its trusted CA signed passes that check.",
                broad_patterns=broad,
            )
        ]
    return []


def _check_aws_role(role: AuthRole) -> list[Finding]:
    found: list[Finding] = []
    c = role.config
    auth_type = c.get("auth_type", "iam")
    if auth_type == "iam":
        arns = [str(a) for a in as_list(c.get("bound_iam_principal_arn"))]
        wildcard = [a for a in arns if _any_account_arn(a)]
        if wildcard:
            accounts = [str(a) for a in as_list(c.get("bound_account_id"))]
            # bound_account_id is only checked on IAM logins that infer an EC2 instance.
            narrowed = bool(accounts) and c.get("inferred_entity_type") == "ec2_instance"
            found.append(
                _role_finding(
                    "VP-AWS-001",
                    role,
                    f"AWS role '{role.name}' accepts IAM principals from any AWS account: {', '.join(wildcard)}"
                    + (f" (narrowed to account {', '.join(accounts)} through the inferred EC2 instance)." if narrowed else "."),
                    wildcard_arns=wildcard,
                    bound_account_id=accounts,
                    account_narrowed=narrowed,
                )
            )
        exact = [a for a in arns if "*" not in a]
        if exact and c.get("resolve_aws_unique_ids") is False:
            found.append(
                _role_finding(
                    "VP-AWS-003",
                    role,
                    f"AWS role '{role.name}' matches IAM principals by ARN only: a principal deleted and recreated with the same name still logs in.",
                    bound_iam_principal_arn=exact,
                )
            )
    elif auth_type == "ec2":
        if not any(as_list(c.get(b)) for b in AWS_EC2_PINNING_BOUNDS):
            found.append(
                _role_finding(
                    "VP-AWS-002",
                    role,
                    f"AWS EC2 role '{role.name}' is not bound to an account, VPC, subnet, IAM role or instance: an instance in any AWS account that matches the remaining bounds can log in.",
                    bound_region=as_list(c.get("bound_region")),
                    bound_ami_id=as_list(c.get("bound_ami_id")),
                )
            )
        if c.get("allow_instance_migration"):
            found.append(
                _role_finding(
                    "VP-AWS-004",
                    role,
                    f"AWS EC2 role '{role.name}' allows instance migration, which weakens the protection against a reused identity document.",
                    disallow_reauthentication=c.get("disallow_reauthentication"),
                )
            )
    return found


# Vault's default (and recommended) max_jwt_exp for GCP IAM logins.
GCP_DEFAULT_JWT_EXP = 900


def _check_gcp_role(role: AuthRole) -> list[Finding]:
    found: list[Finding] = []
    c = role.config
    accounts = [str(a) for a in as_list(c.get("bound_service_accounts"))]
    projects = [str(p) for p in as_list(c.get("bound_projects"))]
    if c.get("type", "iam") == "iam":
        if "*" in accounts and not projects:
            found.append(
                _role_finding(
                    "VP-GCP-001",
                    role,
                    f"GCP IAM role '{role.name}' accepts every service account (bound_service_accounts=*) with no bound_projects: a service account in any GCP project can log in.",
                    allow_gce_inference=c.get("allow_gce_inference"),
                )
            )
        elif "*" in accounts:
            found.append(
                _role_finding(
                    "VP-GCP-003",
                    role,
                    f"GCP IAM role '{role.name}' accepts every service account in {'projects' if len(projects) > 1 else 'project'} {', '.join(projects)}.",
                    bound_projects=projects,
                )
            )
        max_exp = _seconds(c.get("max_jwt_exp"))
        if max_exp > GCP_DEFAULT_JWT_EXP:
            found.append(
                _role_finding(
                    "VP-GCP-004",
                    role,
                    f"GCP IAM role '{role.name}' accepts signed JWTs valid for up to {max_exp}s (default {GCP_DEFAULT_JWT_EXP}s), so a stolen JWT stays replayable longer.",
                    max_jwt_exp_seconds=max_exp,
                )
            )
    elif c.get("type") == "gce":
        # A service account email belongs to one project, so an exact one pins the project too.
        if not projects and not [a for a in accounts if a != "*"]:
            found.append(
                _role_finding(
                    "VP-GCP-002",
                    role,
                    f"GCP GCE role '{role.name}' is not bound to a project or service account: an instance in any GCP project that matches the remaining bounds can log in.",
                    bound_zones=as_list(c.get("bound_zones")),
                    bound_regions=as_list(c.get("bound_regions")),
                    bound_instance_groups=as_list(c.get("bound_instance_groups")),
                    bound_labels=c.get("bound_labels") or {},
                )
            )
    return found


# Resource bounds Vault verifies at login by fetching the VM or scale set; bound_locations also
# narrows, but any VM in the tenant in that region matches it.
AZURE_RESOURCE_BOUNDS = ("bound_subscription_ids", "bound_resource_groups", "bound_scale_sets")


def _azure_specific(ids: list[str]) -> bool:
    # Vault globs only on a list that is exactly ["*"]; a "*" next to other IDs is matched literally.
    return bool(ids) and ids != ["*"]


def _check_azure_role(role: AuthRole) -> list[Finding]:
    c = role.config
    sps = [str(s) for s in as_list(c.get("bound_service_principal_ids"))]
    groups = [str(g) for g in as_list(c.get("bound_group_ids"))]
    locations = [str(loc) for loc in as_list(c.get("bound_locations"))]
    if _azure_specific(sps) or _azure_specific(groups):
        identity = "pinned"
    elif (sps == ["*"]) != (groups == ["*"]):
        identity = "wildcard"
    else:
        # Both empty or both "*": login refuses the role since plugin v0.21.0 (Vault 1.20).
        return [
            _role_finding(
                "VP-AZURE-002",
                role,
                f"Azure role '{role.name}' binds no specific service principal or group: Vault 1.20+ refuses every login through it, "
                "older versions admit any identity in the tenant that matches its other bounds.",
                bound_service_principal_ids=sps,
                bound_group_ids=groups,
                bound_locations=locations,
                **{b: [str(v) for v in as_list(c.get(b))] for b in AZURE_RESOURCE_BOUNDS},
            )
        ]
    found: list[Finding] = []
    if identity == "wildcard" and not any(as_list(c.get(b)) for b in AZURE_RESOURCE_BOUNDS):
        field_name = "bound_service_principal_ids" if sps == ["*"] else "bound_group_ids"
        found.append(
            _role_finding(
                "VP-AZURE-001",
                role,
                f"Azure role '{role.name}' binds {field_name}=* with no subscription, resource group or scale set bound: any identity in the configured tenant"
                + (f" with a VM in {', '.join(locations)}" if locations else "")
                + " can log in.",
                wildcard_field=field_name,
                bound_locations=locations,
            )
        )
    scoped = [b for b in ("bound_resource_groups", "bound_scale_sets") if as_list(c.get(b))]
    if scoped and not as_list(c.get("bound_subscription_ids")) and not _azure_specific(sps):
        found.append(
            _role_finding(
                "VP-AZURE-003",
                role,
                f"Azure role '{role.name}' binds {' and '.join(scoped)} without bound_subscription_ids: a same-named resource in any subscription of the tenant matches.",
                **{b: [str(v) for v in as_list(c.get(b))] for b in scoped},
                bound_group_ids=groups,
            )
        )
    return found


def roles_data(data: RoleData) -> dict[str, Any]:
    return {"namespaces": [display_namespace(n) for n in data.namespaces], "roles": [r.to_dict() for r in data.roles]}


# --------------------------------------------------------------------------- pki


@dataclass
class Issuer:
    namespace: str
    mount: str
    issuer_id: str
    config: dict[str, Any]
    cert: dict[str, Any] | None  # parsed certificate facts, never the PEM

    @property
    def path(self) -> str:
        return f"{self.mount}issuer/{self.issuer_id}"

    def to_dict(self) -> dict[str, Any]:
        return {"namespace": display_namespace(self.namespace), "mount": self.mount, "issuer_id": self.issuer_id, "config": self.config, "certificate": self.cert}


@dataclass
class PkiMount:
    namespace: str
    mount: str
    auto_tidy: dict[str, Any] | None = None
    crl: dict[str, Any] | None = None
    urls: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"namespace": display_namespace(self.namespace), "mount": self.mount, "auto_tidy": self.auto_tidy, "crl": self.crl, "urls": self.urls}


@dataclass
class PkiData:
    namespaces: list[str] = field(default_factory=list)
    mounts: list[PkiMount] = field(default_factory=list)
    issuers: list[Issuer] = field(default_factory=list)


def describe_certificate(pem: str) -> dict[str, Any] | None:
    """Facts needed by the PKI rules; None when the PEM can't be parsed."""
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except (ValueError, TypeError):
        return None
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "rsa", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "ec", key.curve.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        key_type, key_bits = "ed25519" if isinstance(key, ed25519.Ed25519PublicKey) else "ed448", None
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "dsa", key.key_size
    else:
        key_type, key_bits = type(key).__name__, None
    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    algorithm = cert.signature_hash_algorithm
    return {
        "common_name": str(common_names[0].value) if common_names else None,
        "not_before": iso(cert.not_valid_before_utc),
        "not_after": iso(cert.not_valid_after_utc),
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_hash": algorithm.name if algorithm else None,
        "self_signed": cert.issuer == cert.subject,
    }


def collect_pki(reader: Reader, coverage: Coverage, namespaces: list[str]) -> PkiData:
    data = PkiData(namespaces=namespaces)
    for ns in namespaces:
        for mount, mount_type in sorted(mounts_of(reader, coverage, "mounts", ns).items()):
            if mount_type != "pki":
                continue
            pki = PkiMount(ns, mount)
            for attr, path, fields in (("auto_tidy", "config/auto-tidy", AUTO_TIDY_FIELDS), ("crl", "config/crl", CRL_FIELDS), ("urls", "config/urls", URL_FIELDS)):
                status, body = attempt(coverage, f"pki.{mount}{path}", lambda p=f"{mount}{path}", n=ns: reader.data(p, namespace=n), ns)
                if status == OK:
                    setattr(pki, attr, pick(body, fields))
            data.mounts.append(pki)
            status, issuers = attempt(coverage, f"pki.{mount}issuers", lambda m=mount, n=ns: reader.list_info(f"{m}issuers", namespace=n), ns)
            for issuer_id in sorted(issuers or {}) if status == OK else []:
                status, body = attempt(coverage, f"pki.{mount}issuer/{issuer_id}", lambda m=mount, i=issuer_id, n=ns: reader.data(f"{m}issuer/{i}", namespace=n), ns)
                if status == OK:
                    data.issuers.append(Issuer(ns, mount, issuer_id, pick(body, ISSUER_FIELDS), describe_certificate(body.get("certificate") or "")))
    return data


def _issuer_finding(rule_id: str, issuer: Issuer, detail: str, **evidence: Any) -> Finding:
    name = issuer.config.get("issuer_name") or None
    cn = (issuer.cert or {}).get("common_name")
    return finding(rule_id, "pki_issuer", issuer.path, detail, namespace=issuer.namespace, mount=issuer.mount, issuer_name=name, common_name=cn, **evidence)


def check_pki(data: PkiData, now: datetime, critical_days: int = PKI_CRITICAL_DAYS, warning_days: int = PKI_WARNING_DAYS) -> list[Finding]:
    found: list[Finding] = []
    mounts = {(m.namespace, m.mount): m for m in data.mounts}
    for issuer in data.issuers:
        cert = issuer.cert or {}
        label = issuer.config.get("issuer_name") or cert.get("common_name") or issuer.issuer_id
        not_after = parse_time(cert.get("not_after"))
        if not_after is not None and not issuer.config.get("revoked"):
            days = (not_after - now).days
            if not_after <= now:
                found.append(_issuer_finding("VP-PKI-001", issuer, f"Issuer '{label}' expired on {cert['not_after']}.", not_after=cert["not_after"], days_left=days))
            elif days < critical_days:
                found.append(
                    _issuer_finding("VP-PKI-002", issuer, f"Issuer '{label}' expires in {days} days ({cert['not_after']}).", not_after=cert["not_after"], days_left=days, threshold_days=critical_days)
                )
            elif days < warning_days:
                found.append(
                    _issuer_finding("VP-PKI-003", issuer, f"Issuer '{label}' expires in {days} days ({cert['not_after']}).", not_after=cert["not_after"], days_left=days, threshold_days=warning_days)
                )
        weak = []
        if cert.get("key_type") in ("rsa", "dsa") and (cert.get("key_bits") or 0) < MIN_RSA_BITS:
            weak.append(f"{cert['key_type']} {cert.get('key_bits')}-bit key")
        if cert.get("key_type") == "ec" and (cert.get("key_bits") or 0) < MIN_EC_BITS:
            weak.append(f"ec {cert.get('key_bits')}-bit key")
        if cert.get("signature_hash") in ("sha1", "md5"):
            weak.append(f"{cert['signature_hash']} signature")
        if weak:
            found.append(_issuer_finding("VP-PKI-007", issuer, f"Issuer '{label}' uses a {', '.join(weak)}.", weaknesses=weak))
        mount = mounts.get((issuer.namespace, issuer.mount))
        mount_urls = as_list((mount.urls or {}).get("issuing_certificates")) if mount else []
        if not as_list(issuer.config.get("issuing_certificates")) and not mount_urls and mount is not None and mount.urls is not None:
            found.append(_issuer_finding("VP-PKI-005", issuer, f"Neither issuer '{label}' nor its mount publishes an issuing-certificates (AIA) URL, so clients can't fetch the chain."))
        if issuer.config.get("leaf_not_after_behavior") == "permit":
            found.append(_issuer_finding("VP-PKI-008", issuer, f"Issuer '{label}' signs leaves whose validity runs past its own expiry (leaf_not_after_behavior=permit)."))
    for mount in data.mounts:
        if mount.auto_tidy is not None and not mount.auto_tidy.get("enabled"):
            found.append(
                finding(
                    "VP-PKI-004",
                    "pki_mount",
                    mount.mount,
                    f"PKI mount '{mount.mount}' has automatic tidy disabled; expired certificates and revocation entries accumulate in storage.",
                    namespace=mount.namespace,
                )
            )
        if mount.crl is not None and mount.crl.get("disable") and mount.crl.get("ocsp_disable"):
            found.append(
                finding(
                    "VP-PKI-006", "pki_mount", mount.mount, f"PKI mount '{mount.mount}' publishes no CRL and answers no OCSP, so revoked certificates can't be detected.", namespace=mount.namespace
                )
            )
    return found


def pki_data(data: PkiData) -> dict[str, Any]:
    return {"namespaces": [display_namespace(n) for n in data.namespaces], "mounts": [m.to_dict() for m in data.mounts], "issuers": [i.to_dict() for i in data.issuers]}


# --------------------------------------------------------------------------- access (offline ACL evaluation)


# Pre-0.9 `policy = "..."` shorthand -> capabilities.
LEGACY_POLICY = {
    "deny": ["deny"],
    "read": ["read", "list"],
    "write": ["create", "read", "update", "delete", "list"],
    "sudo": ["create", "read", "update", "delete", "list", "sudo"],
}
HCL_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|<<-?(\w+)\n.*?\n\s*\1|[{}\[\]=,]|[^\s{}\[\]=,"#]+', re.S)
HCL_COMMENT = re.compile(r'"(?:[^"\\]|\\.)*"|(#[^\n]*|//[^\n]*|/\*.*?\*/)', re.S)


@dataclass(frozen=True)
class AclRule:
    policy: str
    path: str
    capabilities: tuple[str, ...]


def _strip_comments(text: str) -> str:
    return HCL_COMMENT.sub(lambda m: m.group(0) if m.group(1) is None else " ", text)


def parse_policy(name: str, text: str) -> list[AclRule]:
    """`path "<glob>" { capabilities = [...] }` blocks of an ACL policy (HCL or JSON); other attributes are ignored."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            body = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{name}: invalid JSON policy") from exc
        paths = body.get("path") or {}
        return [AclRule(name, glob, tuple(_capabilities(rule or {}))) for glob, rule in paths.items()]
    tokens = [m.group(0) for m in HCL_TOKEN.finditer(_strip_comments(text))]
    rules, i = [], 0
    while i < len(tokens):
        if tokens[i] == "path" and i + 2 < len(tokens) and tokens[i + 1].startswith('"') and tokens[i + 2] == "{":
            glob = json.loads(tokens[i + 1])
            i, body = _block(tokens, i + 3)
            rules.append(AclRule(name, glob, tuple(_capabilities(body))))
        else:
            i += 1
    if not rules and "path" in tokens:
        raise ValueError(f"{name}: no path blocks could be parsed")
    return rules


def _block(tokens: list[str], i: int) -> tuple[int, dict[str, Any]]:
    """Parse attributes until the matching `}`; returns (index after it, {key: value}) for top-level keys."""
    body: dict[str, Any] = {}
    while i < len(tokens) and tokens[i] != "}":
        key = tokens[i].strip('"')
        if i + 1 < len(tokens) and tokens[i + 1] == "=":
            i, body[key] = _value(tokens, i + 2)
        elif i + 1 < len(tokens) and tokens[i + 1] == "{":  # nested block without `=`
            i, body[key] = _block(tokens, i + 2)
        else:
            i += 1
    return i + 1, body


def _value(tokens: list[str], i: int) -> tuple[int, Any]:
    token = tokens[i]
    if token == "[":
        items, i = [], i + 1
        while tokens[i] != "]":
            if tokens[i] != ",":
                i, item = _value(tokens, i)
                items.append(item)
            else:
                i += 1
        return i + 1, items
    if token == "{":
        return _block(tokens, i + 1)
    if token.startswith('"'):
        return i + 1, json.loads(token)
    return i + 1, token


def _capabilities(body: dict[str, Any]) -> list[str]:
    caps = [str(c) for c in as_list(body.get("capabilities"))]
    if not caps and isinstance(body.get("policy"), str):
        caps = LEGACY_POLICY.get(body["policy"], [])
    return caps


def load_policies(sources: list[str]) -> tuple[list[AclRule], list[str], list[dict[str, str]]]:
    """Rules from .hcl/.json files or directories of them; the policy name is the file stem."""
    files: list[Path] = []
    for source in sources:
        path = Path(source).expanduser()
        if path.is_dir():
            files += sorted(p for p in path.rglob("*") if p.suffix in (".hcl", ".json") and p.is_file())
        elif path.is_file():
            files.append(path)
        else:
            raise SystemExit(f"error: policy source not found: {source}")
    rules, loaded, unparsed = [], [], []
    for file in files:
        try:
            parsed = parse_policy(file.stem, file.read_text())
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            unparsed.append({"file": str(file), "reason": type(exc).__name__})
            continue
        rules += parsed
        loaded.append(file.stem)
    return rules, loaded, unparsed


def glob_regex(glob: str) -> re.Pattern[str]:
    """Vault ACL path matching: `+` is exactly one segment, a trailing `*` is any suffix."""
    prefix = glob[:-1] if glob.endswith("*") else glob
    pattern = "/".join("[^/]+" if part == "+" else re.escape(part) for part in prefix.split("/"))
    return re.compile(f"^{pattern}{'.*' if glob.endswith('*') else ''}$", re.S)


def glob_priority(glob: str) -> tuple[int, int, int, int, str]:
    """Higher sorts first, per Vault's priority matching for overlapping wildcard paths."""
    first = min([i for i, ch in enumerate(glob) if ch in "+*"] or [len(glob)])
    return (first, 0 if glob.endswith("*") else 1, -glob.split("/").count("+"), len(glob), glob)


def is_wildcard(glob: str) -> bool:
    return glob.endswith("*") or "+" in glob.split("/")


def effective_capabilities(rules: list[AclRule], path: str) -> dict[str, Any]:
    """Capabilities a token holding all `rules` has on `path`, as Vault decides it.

    Rules for the same glob are merged (deny wins). An exact match beats any wildcard; among
    wildcard matches the single highest-priority glob decides. No match means implicit deny.
    """
    merged: dict[str, set[str]] = {}
    sources: dict[str, set[str]] = {}
    for rule in rules:
        merged.setdefault(rule.path, set()).update(rule.capabilities)
        sources.setdefault(rule.path, set()).add(rule.policy)
    match = path if path in merged and not is_wildcard(path) else None
    if match is None:
        candidates = [g for g in merged if is_wildcard(g) and glob_regex(g).match(path)]
        match = max(candidates, key=glob_priority) if candidates else None
    # Reported like sys/capabilities: an implicit deny is ["deny"] too; `decision` tells them apart.
    if match is None:
        return {"capabilities": ["deny"], "decision": "implicit_deny", "matched_path": None, "policies": []}
    caps = merged[match]
    if "deny" in caps:
        return {"capabilities": ["deny"], "decision": "explicit_deny", "matched_path": match, "policies": sorted(sources[match])}
    if not caps:
        return {"capabilities": ["deny"], "decision": "implicit_deny", "matched_path": match, "policies": sorted(sources[match])}
    return {"capabilities": sorted(caps), "decision": "allow", "matched_path": match, "policies": sorted(sources[match])}


def access_document(rules: list[AclRule], loaded: list[str], unparsed: list[dict[str, str]], paths: list[str], capability: str | None, started: datetime) -> dict[str, Any]:
    by_policy: dict[str, list[AclRule]] = {}
    for rule in rules:
        by_policy.setdefault(rule.policy, []).append(rule)
    queries = []
    for path in paths:
        per_policy = []
        for name in sorted(by_policy):
            result = effective_capabilities(by_policy[name], path)
            if result["matched_path"] is not None:
                per_policy.append({"policy": name, "capabilities": result["capabilities"], "matched_path": result["matched_path"]})
        combined = effective_capabilities(rules, path)
        query: dict[str, Any] = {"path": path, "combined": combined, "per_policy": per_policy}
        if capability:
            query["capability"] = capability
            query["granted_by"] = sorted(p["policy"] for p in per_policy if capability in p["capabilities"])
            query["combined_allows"] = capability in combined["capabilities"]
        queries.append(query)
    return {
        "run": {"tool": TOOL_NAME, "tool_version": TOOL_VERSION, "schema_version": SCHEMA_VERSION, "generated_at": iso(started), "mode": "offline"},
        "policies": {"loaded": sorted(loaded), "rules": len(rules), "unparsed": unparsed},
        "queries": queries,
    }


# --------------------------------------------------------------------------- diff

DIFF_RUN_KEYS = ("cluster_name", "start_namespace", "edition")


def load_findings_document(source: str) -> dict[str, Any]:
    try:
        document = json.loads(Path(source).expanduser().read_text())
    except FileNotFoundError:
        raise SystemExit(f"error: file not found: {source}") from None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {source} is not a JSON file: {exc}") from None
    if not (
        isinstance(document, dict)
        and isinstance(document.get("run"), dict)
        and isinstance(document.get("findings"), list)
        and all(isinstance(f, dict) and "fingerprint" in f and "rule_id" in f for f in document["findings"])
    ):
        raise SystemExit(f"error: {source} is not a vault-posture findings document (audit, roles, pki, quotas or security)")
    return document


def count_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = Counter(f.get("severity") for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "by_rule": dict(sorted(Counter(f["rule_id"] for f in findings).items())),
    }


def _issuer_key(f: dict[str, Any]) -> tuple[Any, ...] | None:
    # A rotated CA gets a new issuer_id (so a new fingerprint) but usually keeps its name.
    evidence = f.get("evidence") or {}
    if (f.get("object") or {}).get("kind") != "pki_issuer" or not evidence.get("issuer_name"):
        return None
    return (f["rule_id"], f.get("namespace"), evidence.get("mount"), evidence["issuer_name"])


def diff_documents(old: dict[str, Any], new: dict[str, Any], started: datetime) -> dict[str, Any]:
    old_by = {f["fingerprint"]: f for f in old["findings"]}
    new_by = {f["fingerprint"]: f for f in new["findings"]}
    resolved = [f for fp, f in old_by.items() if fp not in new_by]
    added = [f for fp, f in new_by.items() if fp not in old_by]
    unchanged = [f for fp, f in new_by.items() if fp in old_by]

    rotated = []
    pending = {key: f for f in added if (key := _issuer_key(f)) is not None}
    for f in list(resolved):
        match = pending.pop(key, None) if (key := _issuer_key(f)) is not None else None
        if match is not None:
            rotated.append({"old": f, "new": match})
            resolved.remove(f)
            added.remove(match)

    warnings = []
    old_run, new_run = old["run"], new["run"]
    for key in DIFF_RUN_KEYS:
        if old_run.get(key) != new_run.get(key):
            warnings.append(f"the runs differ in {key} ({old_run.get(key)!r} vs {new_run.get(key)!r}): they may not describe the same scope")
    for label, document in (("old", old), ("new", new)):
        if not (document.get("coverage") or {}).get("complete", False):
            warnings.append(f"the {label} run's coverage is incomplete: a resolved or new finding may just be unread")
    old_at, new_at = parse_time(old_run.get("generated_at")), parse_time(new_run.get("generated_at"))
    if old_at and new_at and new_at < old_at:
        warnings.append("the new run is older than the old one: the files may be in the wrong order")

    return {
        "run": {"tool": TOOL_NAME, "tool_version": TOOL_VERSION, "schema_version": SCHEMA_VERSION, "generated_at": iso(started), "mode": "offline"},
        "runs": {"old": old_run, "new": new_run},
        "warnings": warnings,
        "summary": {"new": count_findings(added), "resolved": count_findings(resolved), "unchanged": len(unchanged), "rotated": len(rotated)},
        "findings": {"new": added, "resolved": resolved, "rotated": rotated, "unchanged": unchanged},
    }


# --------------------------------------------------------------------------- documents


def run_block(probe: dict[str, Any], addr: str, started: datetime, namespace: str = "") -> dict[str, Any]:
    version = str(probe.get("version") or "")
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": iso(started),
        "cluster_name": probe.get("cluster_name") or "vault",
        "vault_addr": addr,
        "vault_version": version,
        "edition": "enterprise" if "+ent" in version else "community",
        "start_namespace": display_namespace(namespace),
    }


def summarise(findings: list[Finding]) -> dict[str, Any]:
    by_severity = Counter(f.rule.severity for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
    }


def build_document(run: dict[str, Any], coverage: Coverage, findings: list[Finding], data: dict[str, Any]) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (SEVERITIES.index(f.rule.severity), f.rule_id, f.namespace, f.object_path or ""))
    return {
        "run": run,
        "coverage": coverage.to_dict(),
        "summary": summarise(ordered),
        "findings": [f.to_dict() for f in ordered],
        "data": data,
    }


def quotas_data(data: QuotaData) -> dict[str, Any]:
    return {"config": data.config, "rate_limit": data.rate_limit, "lease_count": data.lease_count}


def security_data(data: SecurityData) -> dict[str, Any]:
    return {
        "generate_root": data.generate_root,
        "generate_recovery_token": data.generate_recovery_token,
        "rekey": data.rekey,
        "rekey_recovery": data.rekey_recovery,
        "key_status": data.key_status,
        "rotate_config": data.rotate_config,
        "external_plugins": [p for p in data.plugins or [] if p.get("builtin") is False] if data.plugins is not None else None,
    }


def write_json(path: Path, document: dict[str, Any]) -> Path:
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=True)
        (path.parent / ".gitignore").write_text("# vault-posture results are confidential: never commit them\n*\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)
    return path


def output_path(output_dir: str, cluster: str, kind: str, ts: datetime) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "-", cluster) or "vault"
    return Path(output_dir).expanduser().resolve() / f"{safe}-{kind}-{ts.strftime('%Y%m%d-%H%M%S')}.json"


def exit_code_for(document: dict[str, Any], fail_on: str | None, fail_on_gaps: bool) -> int:
    if fail_on:
        threshold = SEVERITIES.index(fail_on)
        if any(SEVERITIES.index(f["severity"]) <= threshold for f in document["findings"]):
            return EXIT_FINDINGS
    if fail_on_gaps and not document["coverage"]["complete"]:
        return EXIT_GAPS
    return EXIT_OK


# --------------------------------------------------------------------------- commands

LIVE_AREAS = ("quotas", "security", "roles", "pki")


def run_checks(args: argparse.Namespace, kind: str, areas: tuple[str, ...]) -> int:
    config, reader, probe = connect(getattr(args, "namespace", None))
    started = utc_now()
    coverage = Coverage()
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    if "quotas" in areas:
        quota_data = collect_quotas(reader, coverage)
        findings += check_quotas(quota_data)
        data["quotas"] = quotas_data(quota_data)
    if "security" in areas:
        security_state = collect_security(reader, coverage)
        findings += check_security(security_state, started, args.key_age_days)
        data["security"] = security_data(security_state)
    if "roles" in areas or "pki" in areas:
        namespaces = discover_namespaces(reader, coverage, config.namespace)
        if "roles" in areas:
            role_state = collect_roles(reader, coverage, namespaces)
            findings += check_roles(role_state)
            data["roles"] = roles_data(role_state)
        if "pki" in areas:
            pki_state = collect_pki(reader, coverage, namespaces)
            findings += check_pki(pki_state, started, args.pki_critical_days, args.pki_warning_days)
            data["pki"] = pki_data(pki_state)
    run = run_block(probe, "<redacted>" if args.redact_addr else config.addr, started, config.namespace)
    document = build_document(run, coverage, findings, data)
    print(write_json(output_path(args.output_dir, run["cluster_name"], kind, started), document))
    return exit_code_for(document, args.fail_on, args.fail_on_gaps)


def cmd_access(args: argparse.Namespace) -> int:
    rules, loaded, unparsed = load_policies(args.policy)
    if not rules:
        raise SystemExit("error: no ACL path rules found in the given policy files")
    started = utc_now()
    document = access_document(rules, loaded, unparsed, args.path, args.capability, started)
    print(write_json(output_path(args.output_dir, "policies", "access", started), document))
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    old, new = load_findings_document(args.old), load_findings_document(args.new)
    started = utc_now()
    document = diff_documents(old, new, started)
    print(write_json(output_path(args.output_dir, str(new["run"].get("cluster_name") or "vault"), "diff", started), document))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_posture.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Env: VAULT_ADDR, VAULT_TOKEN (required for live subcommands); VAULT_CACERT, VAULT_SKIP_VERIFY, VAULT_NAMESPACE, VAULT_POSTURE_OUTPUT_DIR (default {DEFAULT_OUTPUT_DIR})",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output-dir", default=os.getenv("VAULT_POSTURE_OUTPUT_DIR") or DEFAULT_OUTPUT_DIR)
    live = argparse.ArgumentParser(add_help=False)
    live.add_argument("--redact-addr", action="store_true", help="write vault_addr as <redacted>")
    live.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 when a finding is at or above this severity")
    live.add_argument("--fail-on-gaps", action="store_true", help="exit 2 when coverage is incomplete")
    live.set_defaults(key_age_days=KEY_AGE_WARNING_DAYS, pki_critical_days=PKI_CRITICAL_DAYS, pki_warning_days=PKI_WARNING_DAYS)
    keys = argparse.ArgumentParser(add_help=False)
    keys.add_argument("--key-age-days", type=int, default=KEY_AGE_WARNING_DAYS, help="barrier key age that triggers VP-SEC-003")
    walk = argparse.ArgumentParser(add_help=False)
    walk.add_argument("--namespace", default=None, help="start namespace for roles/pki (default: VAULT_NAMESPACE or root); descendants are included")
    pki = argparse.ArgumentParser(add_help=False)
    pki.add_argument("--pki-critical-days", type=int, default=PKI_CRITICAL_DAYS, help="issuer expiry window for VP-PKI-002")
    pki.add_argument("--pki-warning-days", type=int, default=PKI_WARNING_DAYS, help="issuer expiry window for VP-PKI-003")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit", parents=[common, live, keys, walk, pki], help="every live check -> posture.json").set_defaults(func=lambda a: run_checks(a, "posture", LIVE_AREAS))
    sub.add_parser("quotas", parents=[common, live], help="rate-limit and lease-count quotas -> quotas.json").set_defaults(func=lambda a: run_checks(a, "quotas", ("quotas",)))
    sub.add_parser("security", parents=[common, live, keys], help="seal operations, barrier key, plugins -> security.json").set_defaults(func=lambda a: run_checks(a, "security", ("security",)))
    sub.add_parser("roles", parents=[common, live, walk], help="auth role bindings per namespace -> roles.json").set_defaults(func=lambda a: run_checks(a, "roles", ("roles",)))
    sub.add_parser("pki", parents=[common, live, walk, pki], help="PKI issuers per namespace -> pki.json (needs vault-posture-pki-reader)").set_defaults(func=lambda a: run_checks(a, "pki", ("pki",)))
    access = sub.add_parser("access", parents=[common], help="offline: effective capabilities of ACL policy files on paths -> access.json")
    access.add_argument("--policy", action="append", required=True, help="ACL policy file (.hcl/.json) or directory; repeatable")
    access.add_argument("--path", action="append", required=True, help="request path to evaluate, e.g. secret/data/app; repeatable")
    access.add_argument("--capability", choices=("create", "read", "update", "patch", "delete", "list", "sudo"), help="also report which policies grant this capability")
    access.set_defaults(func=cmd_access)
    diff = sub.add_parser("diff", parents=[common], help="offline: compare two findings documents by fingerprint -> diff.json")
    diff.add_argument("old", help="the earlier findings document (audit, roles, pki, quotas or security)")
    diff.add_argument("new", help="the later findings document")
    diff.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return EXIT_INTERRUPTED
    except SystemExit as exc:
        if isinstance(exc.code, str):
            log(exc.code)
            return EXIT_FATAL
        raise


if __name__ == "__main__":
    sys.exit(main())
