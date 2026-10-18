# claude-demo: vault-posture skill

Read-only HashiCorp Vault security posture skill. See README.md for usage and layout.

## Conventions

- The skill is one self-contained `uv run --script` file: `skills/vault-posture/scripts/vault_posture.py`. Keep its PEP 723 dependencies in step with `pyproject.toml`; add no imports from elsewhere in the repo.
- Read-only is the product. Vault access goes only through `Reader` (GET only). A new endpoint needs: a grant in `policies/vault-posture-readonly.hcl` (read/list only), a field allowlist, and a coverage scope.
- Split each area into `collect_*` (I/O, returns a dataclass) and `check_*` (pure, takes the dataclass and `now`). Unit tests target `check_*`; `FakeReader` in `tests/conftest.py` drives `collect_*`.
- A new rule needs: an entry in `RULES`, a row in `references/rules.md` (the test enforces it), a firing and a quiet unit test, and seeding in `scripts/seed_findings.sh` if it's live-testable.
- Before pushing: `task lint` and `task test`. With Docker: `task test:e2e`.
