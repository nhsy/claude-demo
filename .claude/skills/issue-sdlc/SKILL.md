---
name: issue-sdlc
description: Find the next GitHub issue or PR in the agent- label pipeline and run its SDLC stage (plan, build, fix feedback). Use when asked to work the issue queue.
disable-model-invocation: true
argument-hint: "[issue-or-pr-number]"
---

# Issue SDLC

Run exactly ONE stage, report, and stop.

PRs are merged with "Rebase and merge", so every commit on an agent/
branch lands on main as written. Make small, self-contained commits
that each build and pass `task test`, with messages in the format
CLAUDE.md gives. Never create merge commits: no `git merge`, always
`git pull --rebase`, and `git rebase origin/main` to catch up with main.
Never leave WIP or fixup commits on the branch. Stage files by name
(`git add path/to/file`); never stage everything at once (`git add .`,
`-A`, `--all`, `-u`, or `git commit -a`): those are denied.

## Tests in this repo

Everything runs through Task (CLAUDE.md "Use Task for everything"):

- Every commit: `task lint && task test`.
- Also `task test:e2e` when the change touches collection, policies or
  seeding (it starts and stops a local `vault server -dev`).
- Never run `task eval` or `task eval:judge` without asking: they spend
  API credits.

A change to the vault-posture skill also follows CLAUDE.md "Rules for
changing the skill" (policy grants via `scripts/gen_policies.py` and
`task policies`, field allowlists, coverage scopes, the new-rule checklist).

## 1. Find work

If $ARGUMENTS holds a number, use that issue or PR. Otherwise check
these queues in order and take the first (oldest) match:

1. Fix: `gh pr list --state open --json number,headRefName,reviewDecision`
   → a PR whose branch starts with `agent/`, reviewDecision is
   CHANGES_REQUESTED, and whose latest commit is older than that review.
2. Build: `gh issue list --state open --label agent-build --search "sort:created-asc" --json number,title --limit 1`
3. Plan: `gh issue list --state open --label agent-ready --search "sort:created-asc" --json number,title --limit 1`

Skip anything labeled agent-working, agent-plan-review or agent-blocked.
If nothing matches, say the queue is empty and list how many issues
wait on a person in agent-plan-review, agent-review and agent-blocked.

For issue stages, claim the issue before any other work:
`gh issue edit N --remove-label <its label> --add-label agent-working`

## 2. Run the stage

### Plan (agent-ready)
1. Read the issue and its comments: `gh issue view N --comments`.
2. Check it against the definition of ready in CLAUDE.md. If anything
   is missing, comment numbered questions, move the label from
   agent-working to agent-blocked, and stop.
3. Explore the code without changing it. Post ONE comment headed
   "## Implementation plan": files to change, approach, test plan
   (which `task` targets, and any new unit or integration tests), risks,
   and the commits you expect to make.
4. Move the label from agent-working to agent-plan-review.

### Build (agent-build)
1. Read the issue, the latest "## Implementation plan" comment and any
   later maintainer comments.
2. `git switch main && git pull --rebase`, then `git switch -c agent/issue-N`.
3. Implement the plan one commit at a time. Write or update tests and
   run `task lint && task test` until they pass at every commit; run
   `task test:e2e` too when the change touches collection, policies or seeding.
4. Review your own diff (`git diff main...`) for bugs, missing tests and
   scope creep, and fix what you find in the commit it belongs to.
5. `git fetch origin && git rebase origin/main`, and run the tests again.
6. `git push -u origin agent/issue-N`, then `gh pr create --draft` with
   a body that fills in .github/pull_request_template.md, starting with
   "Closes #N".
7. Comment the PR link on the issue. Move the label from agent-working
   to agent-review.
If tests can't pass or the plan doesn't fit the code, comment why,
move the label to agent-blocked, and stop.

### Fix (agent/ PR with changes requested)
1. Read the review: `gh pr view P --comments`.
2. `git switch` to the PR branch and `git pull --rebase`.
3. Make the requested changes as new, self-contained commits with clear
   messages. Run `task lint && task test` (and `task test:e2e` when
   relevant) until they pass.
4. `git fetch origin && git rebase origin/main`, run the tests again, then
   `git push --force-with-lease origin agent/<branch>`.
5. `gh pr comment P` listing what you changed.
The issue stays agent-review.

## 3. Report

One line: the issue or PR, the stage run, the outcome, the new label,
and any link. Then stop.

## Never

Merge PRs, close issues, push to main, force-push anything outside an
agent/ branch, or touch issues without an agent- label.
