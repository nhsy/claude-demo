#!/usr/bin/env python3
"""Read-only HashiCorp Vault security posture collector for the vault-posture Claude skill.

Subcommands write small JSON files (mode 0600) and print only the written paths on
stdout; diagnostics go to stderr. Every request is an HTTP GET (lists use ?list=true):
nothing here writes to Vault.

  audit     every live check below                  -> {cluster}-posture-{ts}.json
  quotas    rate-limit and lease-count quotas        -> {cluster}-quotas-{ts}.json
  security  root/recovery token generation, rekey,  -> {cluster}-security-{ts}.json
            barrier key age and rotation, plugin catalog

Complements the vault-ops skill (health, inventory, policies, usage): rule IDs are VP-*.
"""

# /// script
# requires-python = ">=3.12"
# dependencies = ["hvac==2.4.0", "requests>=2.32,<3"]
#
# [tool.uv]
# exclude-newer = "2026-10-05T00:00:00Z"
# ///

from __future__ import annotations

import argparse
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
from hvac import exceptions as hvac_exc

TOOL_NAME = "vault-posture"
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

EXIT_OK, EXIT_FATAL, EXIT_GAPS, EXIT_FINDINGS, EXIT_INTERRUPTED = 0, 1, 2, 3, 130

# Relative to the working directory (the user's project), so Claude can read results without
# leaving it. A directory the script creates gets a catch-all .gitignore: results are never committed.
DEFAULT_OUTPUT_DIR = ".tmp/vault-posture"

# VP-SEC-003: barrier key age that warrants a rotation review.
KEY_AGE_WARNING_DAYS = 365

# 404 bodies for an Enterprise-only path on Community: "enterprise-only feature" (2.x), "unsupported path" (older).
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
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    object_kind: str
    object_path: str | None
    detail: str
    evidence: MappingProxyType = field(default_factory=lambda: MappingProxyType({}), compare=False, hash=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.object_kind}|{self.object_path or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "title": self.rule.title,
            "object": {"kind": self.object_kind, "path": self.object_path},
            "detail": self.detail,
            "evidence": dict(sorted(self.evidence.items())),
        }


def finding(rule_id: str, object_kind: str, object_path: str | None, detail: str, **evidence: Any) -> Finding:
    return Finding(rule_id, object_kind, object_path, detail, MappingProxyType(evidence))


# --------------------------------------------------------------------------- helpers


def pick(source: dict[str, Any] | None, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: source[k] for k in fields if source and k in source}


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

    @classmethod
    def from_env(cls) -> Config:
        addr = os.getenv("VAULT_ADDR", "")
        token = os.getenv("VAULT_TOKEN", "")
        if not addr or not token:
            raise SystemExit("error: VAULT_ADDR and VAULT_TOKEN must be set in the environment")
        skip = os.getenv("VAULT_SKIP_VERIFY", "").lower() in ("1", "true")
        verify: bool | str = False if skip else (os.getenv("VAULT_CACERT") or True)
        if verify is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return cls(addr=addr.rstrip("/"), token=token, verify=verify)


class Reader:
    """The only route to Vault, and GET-only: lists are GET ?list=true, so no other verb is ever sent."""

    def __init__(self, config: Config):
        self.config = config
        session = requests.Session()
        # hvac lets a passed-in session's verify override its own, so TLS settings live on the session.
        session.verify = config.verify
        self._client = hvac.Client(url=config.addr, token=config.token, verify=config.verify, session=session)

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET /v1/<path>; raises hvac exceptions (InvalidPath on 404, Forbidden on 403, ...)."""
        response = self._client.adapter.get(f"/v1/{path}", params=params)
        return response if isinstance(response, dict) else {}

    def data(self, path: str) -> dict[str, Any]:
        payload = self.get(path)
        return payload["data"] if isinstance(payload.get("data"), dict) else payload

    def list(self, path: str) -> list[str]:
        return list(self.get(path, params={"list": "true"}).get("data", {}).get("keys") or [])

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


def connect() -> tuple[Config, Reader, dict[str, Any]]:
    config = Config.from_env()
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

    def record(self, scope: str, status: str, detail: str | None = None) -> None:
        entry = {"scope": scope, "status": status}
        if detail:
            entry["detail"] = detail
        self.scopes.append(entry)

    def status(self, scope: str) -> str | None:
        return next((s["status"] for s in self.scopes if s["scope"] == scope), None)

    @property
    def complete(self) -> bool:
        return not any(s["status"] in (DENIED, ERROR) for s in self.scopes)

    def to_dict(self) -> dict[str, Any]:
        return {"complete": self.complete, "scopes": sorted(self.scopes, key=lambda s: s["scope"])}


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


def attempt(coverage: Coverage, scope: str, call: Any) -> tuple[str, Any]:
    """Run one read, record its coverage status and return (status, result or None)."""
    try:
        result = call()
    except (hvac_exc.VaultError, requests.exceptions.RequestException) as exc:
        status = classify(exc)
        coverage.record(scope, status, sanitise_error(exc) if status == ERROR else None)
        return status, None
    coverage.record(scope, OK)
    return OK, result


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


# --------------------------------------------------------------------------- documents


def run_block(probe: dict[str, Any], addr: str, started: datetime) -> dict[str, Any]:
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
    }


def summarise(findings: list[Finding]) -> dict[str, Any]:
    by_severity = Counter(f.rule.severity for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "by_rule": dict(sorted(Counter(f.rule_id for f in findings).items())),
    }


def build_document(run: dict[str, Any], coverage: Coverage, findings: list[Finding], data: dict[str, Any]) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (SEVERITIES.index(f.rule.severity), f.rule_id, f.object_path or ""))
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


def run_checks(args: argparse.Namespace, kind: str, quotas: bool, security: bool) -> int:
    config, reader, probe = connect()
    started = utc_now()
    coverage = Coverage()
    findings: list[Finding] = []
    data: dict[str, Any] = {}
    if quotas:
        quota_data = collect_quotas(reader, coverage)
        findings += check_quotas(quota_data)
        data["quotas"] = quotas_data(quota_data)
    if security:
        security_state = collect_security(reader, coverage)
        findings += check_security(security_state, started, args.key_age_days)
        data["security"] = security_data(security_state)
    run = run_block(probe, "<redacted>" if args.redact_addr else config.addr, started)
    document = build_document(run, coverage, findings, data)
    print(write_json(output_path(args.output_dir, run["cluster_name"], kind, started), document))
    return exit_code_for(document, args.fail_on, args.fail_on_gaps)


def cmd_audit(args: argparse.Namespace) -> int:
    return run_checks(args, "posture", quotas=True, security=True)


def cmd_quotas(args: argparse.Namespace) -> int:
    return run_checks(args, "quotas", quotas=True, security=False)


def cmd_security(args: argparse.Namespace) -> int:
    return run_checks(args, "security", quotas=False, security=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault_posture.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Env: VAULT_ADDR, VAULT_TOKEN (required); VAULT_CACERT, VAULT_SKIP_VERIFY, VAULT_POSTURE_OUTPUT_DIR (default {DEFAULT_OUTPUT_DIR})",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output-dir", default=os.getenv("VAULT_POSTURE_OUTPUT_DIR") or DEFAULT_OUTPUT_DIR)
    common.add_argument("--redact-addr", action="store_true", help="write vault_addr as <redacted>")
    common.add_argument("--fail-on", choices=SEVERITIES, help="exit 3 when a finding is at or above this severity")
    common.add_argument("--fail-on-gaps", action="store_true", help="exit 2 when coverage is incomplete")
    keys = argparse.ArgumentParser(add_help=False)
    keys.add_argument("--key-age-days", type=int, default=KEY_AGE_WARNING_DAYS, help="barrier key age that triggers VP-SEC-003")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit", parents=[common, keys], help="every live check -> posture.json").set_defaults(func=cmd_audit)
    sub.add_parser("quotas", parents=[common], help="rate-limit and lease-count quotas -> quotas.json").set_defaults(func=cmd_quotas, key_age_days=KEY_AGE_WARNING_DAYS)
    sub.add_parser("security", parents=[common, keys], help="seal operations, barrier key, plugins -> security.json").set_defaults(func=cmd_security)
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
