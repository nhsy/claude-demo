"""The token policy grants every path the script reads, and nothing beyond read/list."""

import re

import vault_posture as vp
from conftest import COMMUNITY_ROUTES, POLICY_PATH, FakeReader, ok

PATH_BLOCK = re.compile(r'path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}', re.M)


def policy_rules():
    rules = {}
    for glob, caps in PATH_BLOCK.findall(POLICY_PATH.read_text()):
        rules[glob] = {c.strip().strip('"') for c in caps.split(",") if c.strip()}
    return rules


def glob_matches(glob, path):
    """Vault ACL matching: `+` is one path segment, a trailing `*` is a prefix."""
    pattern = "^" + re.escape(glob).replace(r"\+", "[^/]+")
    pattern = pattern[:-2] + ".*" if glob.endswith("*") else pattern + "$"
    return re.match(pattern, path) is not None


def capabilities_for(path, rules):
    matched = [caps for glob, caps in rules.items() if glob_matches(glob, path)]
    return set().union(*matched) if matched else set()


def test_policy_only_grants_read_list_or_deny():
    rules = policy_rules()
    assert rules, "no path blocks parsed"
    for glob, caps in rules.items():
        assert caps <= {"read", "list"} or caps == {"deny"}, glob


def test_every_path_the_script_reads_is_granted():
    # Enterprise shape: lease-count quotas exist, so their list and read paths are exercised too.
    routes = dict(COMMUNITY_ROUTES)
    routes[("sys/quotas/lease-count", True)] = ok({"keys": ["global"]})
    routes[("sys/quotas/lease-count/global", False)] = ok({"name": "global", "type": "lease-count", "path": "", "max_leases": 1000})
    reader = FakeReader(routes)
    reader.get("auth/token/lookup-self")
    vp.collect_quotas(reader, vp.Coverage())
    vp.collect_security(reader, vp.Coverage())
    rules = policy_rules()
    for path, is_list in set(reader.calls):
        needed = "list" if is_list else "read"
        acl_path = path + "/" if is_list else path  # Vault checks lists against the path with a trailing slash
        caps = capabilities_for(acl_path, rules)
        assert needed in caps and "deny" not in caps, f"{needed} on {acl_path}"


def test_credential_paths_are_denied():
    rules = policy_rules()
    for path in ("database/creds/app", "pki/issue/web", "ssh/sign/ops", "sys/wrapping/unwrap"):
        assert "deny" in capabilities_for(path, rules), path
