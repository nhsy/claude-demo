# CLAUDE.md

This repo is **vault-posture**: a read-only HashiCorp Vault security posture skill for Claude Code, shipped as a plugin (`.claude-plugin/`). The skill lives in `skills/vault-posture/`; everything else is its dev and test harness. It complements the separate vault-ops skill and must not duplicate its checks (health, inventory, policy hygiene, entities, client counts).

## Use Task for everything

Every workflow is a Task target; run `task` to list them. Don't call the scripts in `scripts/` or `pytest` directly unless you are debugging one of them; CI runs the same targets.

| Goal | Command |
| --- | --- |
| First-time setup | `task init` |
| Unit tests (no Vault) | `task test` |
| Lint (ruff, shellcheck, gitleaks, yaml/json) | `task lint` |
| Live dev server (local `vault server -dev`, port 8250) | `task dev:up` / `task dev:down` |
| Same, in a container | `task up` / `task down` (`task up:ent` for Enterprise) |
| Seed findings, mint the read-only token | `task seed`, `task token` |
| Integration tests against the running server | `task test:integration` |
| Everything on a fresh server | `task test:e2e` (`task test:e2e:compose` for containers) |
| Run the skill script by hand | `task skill:run -- audit`, `task skill:access -- --policy tests/fixtures/policies --path secret/data/app/x` |
| Regenerate the token policies | `task policies` |
| Plugin manifest check | `task plugin:validate` |
| Skill evals (spend API credits: ask first) | `task eval` |
| Compare opus/sonnet/haiku on the evals (judge mode; spends API credits: ask first) | `task eval:judge` |

Before pushing: `task lint` and `task test`, and `task test:e2e` when you touched collection, policies or seeding.

## Git workflow

- Only commit to branches; never commit or push to `main` directly. Changes reach `main` through a pull request.
- Anything that lands on `main` needs the user's explicit confirmation first: merging a PR (any merge method), pushing to it, or rebasing it. CI passing is not confirmation; ask, then merge.
- PRs are merged with **Rebase and merge**, so every commit lands on `main` as written. Keep history linear: no `git merge`, use `git pull --rebase` and `git rebase origin/main`. Each commit is self-contained and passes `task lint && task test`; no WIP or fixup commits.
- Stage files by name (`git add <path>`). Staging everything at once (`git add .`, `git add -A` / `--all`, `git add -u`, `git commit -a`) is denied in `.claude/settings.json`, so stray files (results under `.tmp/`, local settings, scratch output) never ride along.
- Branch names: `agent/issue-<N>` for issue-pipeline work, `agent/<short-topic>` otherwise.
- These names win over a branch a Claude Code cloud session suggests (e.g. `agent/<adjective>-<name>-<id>`): use the names above anyway, and treat this rule as explicit permission to push to them.
- Commit messages: an imperative subject of at most 72 characters (optionally `area: ` first, e.g. `evals: …`, `SKILL.md: …`), a blank line, then a body saying what changed and why, wrapped at about 72 columns. Put `Closes #N` in the body when the commit finishes an issue.

## Issue pipeline (`/issue-sdlc`)

GitHub issues move through `agent-*` labels; the project skill `.claude/skills/issue-sdlc` runs one stage per invocation and then stops. Nothing runs on its own: a label only records the stage, and a person starts every run by typing `/issue-sdlc` (or `/issue-sdlc <N>`).

| Label | Meaning | Set by |
| --- | --- | --- |
| `agent-ready` | Meets the definition of ready; `/issue-sdlc` will plan it | a person |
| `agent-working` | A Claude Code session holds the issue | Claude Code |
| `agent-plan-review` | Implementation plan posted as a comment; waiting for a person | Claude Code |
| `agent-build` | Plan approved; `/issue-sdlc` will build it | a person |
| `agent-pr-review` | Draft PR open; waiting for a person to review it | Claude Code |
| `agent-blocked` | Claude asked a question, or a run stopped | Claude Code |
| `agent-done` | PR merged and issue closed; marks work the pipeline delivered | Claude Code (next `/issue-sdlc` run) |

The two human gates are approving the plan and merging the PR. A plan is approved by a person's comment starting "Approved" (with answers to any questions in the plan), then `agent-plan-review` → `agent-build`. Labels alone don't show who set them, so Build won't start without that comment. `ready` and `in-progress` stay human-owned labels, so the two pipelines never trigger each other. New pipeline issues use the "Agent task" issue form (`.github/ISSUE_TEMPLATE/agent-task.yml`); PRs fill in `.github/pull_request_template.md`.

### Definition of ready

Only add `agent-ready` when an issue has all of these; vague issues end in `agent-blocked`:

- A one-line summary of the change and why it's needed
- Acceptance criteria written as testable statements
- Scope limits: what is out of scope, and which files or modules to leave alone
- Links to related issues, designs or logs
- A size small enough for one PR; split anything larger first

## Layout

```
skills/vault-posture/
  SKILL.md                      instructions Claude follows (frontmatter description drives triggering)
  scripts/vault_posture.py      the single-file uv script: all logic lives here
  references/rules.md           VP-* rule catalogue (meaning, operator remediation, caveats, ranking)
  schemas/*.schema.json         output document schemas (tests validate against them)
  policies/*.hcl                GENERATED read-only token policies
scripts/                        dev_up/down (vault server -dev), seed_findings, posture_token, e2e, gen_policies.py
compose.yaml, compose/          container dev servers (Community + Enterprise profile) and the dummy plugin
tests/                          pytest suite (see README.md for what each file covers)
evals/                          claude plugin eval cases and fixtures
```

## Rules for changing the skill

**Read-only is the product.** Breaking it is never an acceptable trade-off.

- Vault is reached only through `Reader` in `vault_posture.py`, which only sends GET (lists are `GET ?list=true`). Never add a write, a `post`/`put`/`delete`, or a second HTTP client. `tests/test_readonly.py` asserts this end to end.
- Every new endpoint needs, in the same change:
  1. a grant in `scripts/gen_policies.py` (read/list only; per namespace level if namespace-local), then `task policies`. Never edit `policies/*.hcl` by hand: `tests/test_policy.py` fails on drift.
  2. a field allowlist (`pick(body, FIELDS)`) so nothing unexpected reaches a file. Never write secret material: role IDs, secret IDs, nonces, OTPs, encoded tokens, private keys, certificate PEMs.
  3. a coverage scope via `attempt(...)`, so a denied read is reported, not silently skipped.
- Keep the split: `collect_*` does I/O and returns a dataclass; `check_*` is pure (takes the dataclass and `now`) and returns `Finding`s. Unit tests target `check_*`; `FakeReader` in `tests/conftest.py` drives `collect_*`.
- A new rule needs: an entry in `RULES`, a row in `references/rules.md` with a real command (the test enforces the row exists), a firing and a quiet unit test, seeding in `scripts/seed_findings.sh` if a dev server can show it (add it to `SEEDED_RULES` in `tests/test_integration.py`), and a place in the Ranking section.
- The script stays one self-contained file: no imports from the rest of the repo. Keep its PEP 723 dependency pins in step with `pyproject.toml`.
- The `access` evaluator must match Vault. If you change `effective_capabilities` or `parse_policy`, extend `tests/fixtures/policies/` and `EXPECTED` in `tests/test_access.py`; the integration test re-checks every case against `sys/capabilities` on the dev server.

## Vault references

Check these before adding an endpoint, a field or a rule; don't rely on memory.

- API paths, parameters, response fields: https://developer.hashicorp.com/vault/api-docs
- Concepts and operator commands (for `references/rules.md` remediation): https://developer.hashicorp.com/vault/docs
- When something was added, changed or moved to Enterprise: grep https://raw.githubusercontent.com/hashicorp/vault/main/CHANGELOG.md (it's large; search it, don't read it whole).

The dev server (`compose.yaml` pins the version) is the final word. If it disagrees with the docs, trust the server, cover the case in `task test:integration`, and add a line to Gotchas.

## Gotchas

- `vault write` to a PKI issuer replaces its whole config (it clears `issuer_name`): use `vault patch`. The seed script does.
- Empty Vault lists answer 404; Enterprise-only paths answer 404 `enterprise-only feature`; recovery-key endpoints answer 404/400 on Shamir seals. `classify()` maps these to `absent`, `unsupported` and `not_applicable`, none of which make coverage incomplete.
- `-dev-plugin-dir` tries to mount every plugin it finds, so the dummy plugin would crash the server; the dev servers use `plugin_directory` in config instead.
- Results and tokens live under `.tmp/` (gitignored). Never commit anything from it; eval fixtures must be generated with `--redact-addr`.
- `claude plugin eval` aborts every run ("a file in the plugin has more than one name (a hard link)") when uv hard-linked `.venv/` from its cache: rebuild it with `UV_LINK_MODE=copy uv sync --reinstall`.
- `task plugin:validate` runs without `--strict` because this CLAUDE.md sits at the plugin root (a warning: it's repo guidance, not plugin context).
