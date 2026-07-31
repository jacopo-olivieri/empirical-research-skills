# Repo conventions — empirical-research-skills

This repo is a shareable, plugin-installable collection of agent skills for
economics/research. When working in it:

## Layout
- One skill per folder: `skills/<kebab-name>/SKILL.md`. Folder name == skill name.
- Optional per-skill `scripts/`, `references/`, `GLOSSARY.md`.
- Drafts go in `skills/in-progress/`, retired skills in `skills/deprecated/` —
  both are ignored by `scripts/link-skills.sh` and should NOT be listed in the
  plugin manifest.

## The plugin manifest is hand-maintained
- `.claude-plugin/plugin.json` has a `"skills"` array listing each **published**
  skill's path (e.g. `"./skills/<name>"`). Add a skill's path here when it's
  ready to ship; remove it if you deprecate the skill.

## Adding / editing a skill
1. Write `skills/<name>/SKILL.md` (frontmatter `name` + `description`; see
   `TEMPLATE-SKILL.md`). Make `description` trigger-focused ("Use when …").
2. Add its path to `plugin.json`.
3. Run `bash scripts/link-skills.sh` to symlink it into `~/.claude/skills`.

## Machine-specific maintenance
Shared-skill migration (`link-shared-skill.sh`) and Stata live-test invocations
are documented in `docs/maintaining.md`.

## Agent-skills configuration (local only)
The issue tracker, the triage labels, the domain documents, and the review-verdict
rules are configured in `CLAUDE.local.md` and in `docs/agents/`. Both are ignored by
git on purpose, so a fresh clone will not contain them. Read them if they are present
on this machine.

## Reporting language
Write every reply to the operator in ASD-STE100 Simplified Technical English.
This applies to conversation only. Files written into this repository — plans,
checklists, `SKILL.md` files, commit messages — keep the normal repository style.

Rules to follow:
- One idea in one sentence. One instruction in one sentence.
- Keep instructions to 20 words or fewer. Keep descriptive sentences to 25 words or fewer.
- Use the active voice.
- Use simple tenses. Do not use a verb form ending in "-ing" as a noun.
- Keep the articles "a", "an", and "the" in place. Do not drop them.
- Use one term for one thing. Do not change to a synonym for variety.
- Prefer a short common word to a long one.

Vocabulary is best-effort. The approved-word dictionary of the specification is not
available in this repository, so word-level conformance is an approximation and must
not be claimed as certified.

## Only publish self-authored skills
`~/.claude/skills` on this machine also contains third-party skills installed
from other people's plugins (e.g. Matt Pocock's). **Do not** copy those into this
repo — publish only skills authored here.
