# Rules for coding agents (Astra and any other agent working in this repo)

These rules apply to every agent session. They exist because throwaway files and
conversation content kept landing in the working tree.

## 1. No throwaway files in the repo

- One-off scripts, reproductions, debug harnesses, before/after comparisons,
  backups, and copies of old code go in `.scratch/` (gitignored) or the OS temp
  directory, never in `src/`, `tests/`, `scripts/`, or `docs/`.
- Delete scratch files when the task is done. Do not leave `_old_*`, `_repro*`,
  `*.bak`, or similar files behind. `.gitignore` catches only two known
  throwaway prefixes (`_old_*`, `_repro*`) so that real underscore-named
  modules stay tracked — it is a backstop, not a substitute for `.scratch/`.
- A file belongs in the repo only if it is product code, a real test, or user-facing
  documentation that the owner asked for.

## 2. Nothing the owner says goes into the repo

- Never write the owner's messages, prompts, pasted reports, chat transcripts,
  conversation summaries, or agent status reports into tracked files.
- Never commit personal details: local paths (`C:\Users\...`, `/home/...`),
  usernames, emails, machine or WSL names. Use placeholders such as
  `/path/to/your/repo`.
- Audits and dogfood runs against local checkouts are personal: write them to
  `docs/audits/` or `atlas/` (both gitignored), not to tracked docs.
- Generated bundles and viewers go in `atlas/` (gitignored).

## 3. Git hygiene

- Stage files by name. Do not `git add -A` / `git add .` without first reading
  `git status` and confirming every file is intended.
- Do not commit or push unless the owner asks. Work on a branch, not `main`.
- Leave the working tree clean at the end of a task: either committed on a
  branch at the owner's request, or reverted.
