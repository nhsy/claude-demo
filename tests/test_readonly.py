"""The read-only contract, end to end through hvac and requests: only GETs leave the process,
and no token or seal-operation secret reaches stdout or a result file."""

import json

import pytest
import vault_posture as vp
from conftest import FAKE_TOKEN, SECRET_MARKERS


@pytest.mark.parametrize("command", ["audit", "quotas", "security"])
def test_only_get_requests_are_sent(fake_vault, tmp_path, command):
    assert vp.main([command, "--output-dir", str(tmp_path)]) == vp.EXIT_OK
    methods = {method for method, _, _ in fake_vault.sent}
    assert methods == {"GET"}
    # Lists go out as GET ?list=true, never as the LIST verb.
    list_paths = {"sys/quotas/rate-limit", "sys/quotas/lease-count"}
    assert all(params.get("list") == "true" for _, path, params in fake_vault.sent if path in list_paths)


def test_no_secrets_in_output(fake_vault, tmp_path, capsys):
    assert vp.main(["audit", "--output-dir", str(tmp_path)]) == vp.EXIT_OK
    out, err = capsys.readouterr()
    written = "".join(p.read_text() for p in tmp_path.glob("*.json"))
    for text in (out, err, written):
        assert FAKE_TOKEN not in text
        for marker in SECRET_MARKERS:
            assert marker not in text


def test_reader_has_no_write_methods():
    public = {name for name in dir(vp.Reader) if not name.startswith("_")}
    assert public == {"get", "data", "list", "probe", "validate"}


def test_output_is_valid_json_with_only_allowlisted_attempt_fields(fake_vault, tmp_path):
    vp.main(["security", "--output-dir", str(tmp_path)])
    document = json.loads(next(tmp_path.glob("*-security-*.json")).read_text())
    assert set(document["data"]["security"]["generate_root"]) == set(vp.ATTEMPT_FIELDS)
