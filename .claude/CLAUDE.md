# Personal Instructions

## Context
Primarily working on Python projects. Default to Python idioms and tooling unless a project clearly indicates otherwise.

## Workflow
- Work briefly: don't narrate plans or reasoning step-by-step as you go. Summarise what you did at the end.
- **If I ask a question, answer it — don't treat it as an implicit command to act.** Only make changes once I've explicitly told you to (e.g. "do it", "go ahead", "make that change"). If a message is ambiguous between a question and an instruction, ask which I mean rather than assuming.
- **Always run tests before declaring a task done.** If no test suite exists, say so rather than skipping the check silently.
- **Never commit to git without asking first**, even if the change is small or you're confident it's correct.
- **Before any change is committed, show a table of diffs** (file, summary of change, lines added/removed) so I can manually validate before you commit. Do this even for small or single-file changes.
- Code style is project-specific — check for a project-level CLAUDE.md, `pyproject.toml`, or `.flake8` before assuming conventions; don't impose a personal style across projects.

## TEST_FREEZE
- `TEST_FREEZE` is a flag I set per project/session (default: unset/false unless I say otherwise).
- **When `TEST_FREEZE=true`: do not modify any test files without asking first.** Before proposing a test change, state exactly what would change, by line number, and why. Wait for explicit approval before editing.
- When unset or `false`, normal test editing rules apply (still subject to the diff-table review above).

## Tooling
- You may use `git` and `gh` directly (status, diff, branch, log, PR creation, etc.) — just hold off on `commit`/`push` until I've approved the diff table above.
- Use **Conventional Commits** for all commit messages (`feat:`, `fix:`, `chore:`, `docs:`, etc.).
- Use **git-cliff** to generate changelogs/releases from commit history rather than writing release notes by hand.
- **Always keep a `CHANGELOG.md` up to date** — regenerate/update it via git-cliff as part of any change, included in the diff table for review.
- **Always ensure Dependabot is set up via `gh`** for repos you're working in (e.g. check for `.github/dependabot.yml`, create/enable it if missing) so dependency update PRs run automatically.
- Use `pytest` for testing, `python3 -m pytest` as the test runner command.

## Communication
- UK English (spelling, grammar, terminology).
- Concise by default; expand only when asked or when the task genuinely needs explanation.
- Correct grammar/syntax/typography in any prose you write, but never in code or code comments unless asked.

## Open items
<!-- Add as they come up: build/lint commands you use often, recurring gotchas, preferred crates, etc. -->
