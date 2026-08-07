# codebase-audit-claude

A skill for auditing empirical research projects. It reviews a codebase against its accompanying paper and produces a spreadsheet listing potential source-code errors, paper–code inconsistencies, and reproducibility issues.

## Scope

The audit covers two classes of problems:

1. **Paper–code consistency.** Does the code match what the paper claims?
2. **Code and pipeline errors.** Does the code contain bugs or pipeline issues that could affect correctness or reproducibility?

The audit does not evaluate the paper’s conceptual arguments, interpretation of results, choice of statistical methods, or broader research design. These paper-level issues should be reviewed separately using a dedicated paper-review workflow such as Refine or an equivalent tool.

## Requirements

### Required Inputs and Software

The required inputs depend on the scope of the audit:

- A **full audit**, covering both paper–code consistency and code and pipeline errors, requires:
  - the research codebase; and
  - the accompanying paper in LaTeX, Markdown, or PDF format.
- A **code-only audit**, covering code and pipeline errors, requires only the research codebase.

All audits also require:

- Access to Claude Code through a supported subscription, Anthropic Console account, or enterprise provider. Audits are token-intensive; for individual users, a Max subscription (5x or 20x) is recommended.
- Git.
- Python 3.10 or later, with the `openpyxl` library installed for creating and validating the output spreadsheet.
  - For projects using Stata, installing and configuring the [`stata`](../stata) skill is also recommended.

### Conditional Requirements

Depending on the project and the scope of the audit, you may also need:

- **A PDF-to-Markdown converter**, if the paper is supplied as a PDF. The skill will attempt to use [Marker](https://github.com/VikParuchuri/marker); alternatively, you can convert the paper manually with a tool such as [Docling](https://docling-project.github.io/docling/) or [MinerU](https://opendatalab.github.io/MinerU/).
- **The project's statistical software** (e.g. Stata, R, Python) when the audit includes runtime checks or targeted reruns.

### Recommended for a Strong Review

The audit is most effective when the project has:

- A clear directory structure and a README or equivalent documentation.
- Each table and figure in the paper can be traced to the code that produces it.
- Well-documented scripts (file headers, comments, etc.), particularly where the code encodes decisions not stated in the paper, such as sample restrictions, variable construction choices, or edge-case handling.
- No extraneous code/data files/results (i.e., old results or analyses that are no longer used).
- Documented data sources, including which datasets are raw inputs, treated as given, restricted, or confidential.
- A traceable data flow from raw inputs through intermediate and analysis datasets to final outputs.

## Use

### Starting an Audit

Start Claude Code from the root directory of the research project using the desktop app, CLI, or VS Code extension. Then run:

```text
/codebase-audit-claude
```

On startup, the skill:

1. Locates the project documentation, main scripts, existing results and, for a Full audit, the accompanying paper. If the paper is supplied as a PDF, the skill converts it to Markdown when Marker is available. Otherwise, it asks you to convert the paper before continuing.
2. Checks for a resumable audit in the `audit/` directory and, if one is found, offers to resume it.

### Configuring the Audit

Before the review begins, the skill asks a short series of setup questions. These determine the audit mode, the permitted checks, the review depth, and any restrictions. Each option is described below.

#### 1. Audit Mode

Select one of two audit modes:

| Mode | What it reviews | Required inputs |
| --- | --- | --- |
| **Full audit** | Paper–code consistency, and code and pipeline errors | Research codebase and accompanying paper |
| **Code-only audit** | Code and pipeline errors only | Research codebase |

See [Requirements](#requirements) for details on the required inputs.

#### 2. Review Level

The review level controls whether, and to what extent, the audit may execute project code.

| Level | Permitted checks | Best suited to |
| --- | --- | --- |
| **Level 1 — Static inspection** | Reviews source code, documentation, data, and existing generated files without executing project code. | Projects that are expensive to run, depend on unavailable software or data, or must be reviewed under tight time or compute constraints. |
| **Level 2 — Targeted execution** | Adds syntax and parser checks, small tests using simulated data, and selective execution of scripts or pipeline stages. Individual checks are limited to 15 minutes by default. | Projects whose components can be tested independently, but for which a complete rerun would be unnecessary or too costly. |
| **Level 3 — Unrestricted execution** | May run any project script or pipeline stage, including a complete rerun, unless explicitly restricted during intake. | Projects that can be executed in full and for which sufficient time, compute, software, and data are available. |

Each level includes everything permitted at the levels below it. Choose based on available time, compute, and token budget: higher levels catch more runtime issues but cost more to run. Level 2 is the default and recommended option for most audits.

#### 3. Review Depth

Review depth determines how thoroughly potential findings are verified after the primary review. It affects:

1. which files receive additional review passes; and
2. whether potential findings are rechecked in batches or individually.

| Depth | Additional file review | Verification of potential findings | Best suited to |
| --- | --- | --- | --- |
| **Shallow** | Files containing at least one potentially serious finding (Severity 3 or higher) receive one additional review pass. | Related findings are rechecked in batches of up to eight by a single subagent. | Large projects, limited Claude usage, or audits where speed and token efficiency are priorities. |
| **Standard** | Every file containing a potential finding receives one additional review pass. | Related findings are rechecked in batches of up to eight by a single subagent. | Most audits. This is the default and recommended option. |
| **Deep** | Every file containing a potential finding receives two additional, independent review passes. | Each potential finding is rechecked individually by a dedicated subagent. | Audits where greater verification confidence justifies substantially higher time and token use. |

Review depth controls only additional file review and finding rechecks. It does not change the scope of the primary review.

Higher depths use more subagents and therefore generally require more time and tokens. Resource use at the **Deep** level can vary considerably with the size of the codebase and the number of potential findings.

#### 4. Access Restrictions and Review Scope

Define access restrictions and adjust the scope of the review.

| Setting | Purpose | Examples |
| --- | --- | --- |
| **Access restrictions** | Set hard limits on what the audit may access or execute. | Confidential data that must not be opened; scripts, commands, or pipeline stages that must not be run. |
| **Review scope** | Define which files and directories fall within the audit. | Excluding caches, archived or exploratory code, import-only mirrors, or third-party dependencies. |

**Access restrictions** apply throughout the audit, regardless of the selected review level. Use an access restriction whenever a file, dataset, command, or action must remain off-limits.

**Review scope** determines which files and directories are reviewed. The skill proposes a set of routine exclusions, typically including:

- the audit’s own files;
- version-control metadata and caches;
- package-manager and virtual-environment directories; and
- archived, exploratory, or import-only copies of code.

The skill may also suggest project-specific exclusions based on the project structure and documentation. You can modify these exclusions before the audit begins.

#### 5. Project Context

Provide any project-specific information that may not be clear from the repository, code, or documentation. This helps the audit interpret the project correctly and prioritise its review.

Useful context may include:

- known issues, suspected errors, or fragile parts of the codebase;
- manual or external steps that are not represented in the repository;
- datasets that are externally supplied, access-restricted, or treated as given;
- unusual conventions, assumptions, or deliberate departures from standard practice;
- computationally expensive steps or limitations of the available environment; and
- scripts, outputs, or parts of the pipeline that warrant particular attention.

Providing project context is optional. It does not exclude other materials from review or cause known issues to be accepted without verification. Any material that must not be accessed must be recorded under [Access Restrictions](#4-access-restrictions-and-review-scope).

#### 6. Model and Reasoning Effort

Configure the model and reasoning effort used by the audit subagents. If you do not specify a model, the subagents use the model selected for the current Claude Code session. For the strongest review, run the session on Opus 5, or set the worker model to `opus` during setup.

Reasoning effort is set separately for each audit stage and does not inherit the current session setting. The audit uses the defaults below.

| Audit stage | Purpose | Default reasoning effort |
| --- | --- | :---: |
| **Project mapping** | Identify the project’s inputs, scripts, dependencies, pipeline stages, and outputs, and trace how they relate to one another. | Medium |
| **Review planning** | Define how the audit will examine the code and pipeline and, for a **Full audit**, compare the paper with the implementation. | Medium |
| **Primary review** | Inspect the relevant project materials to identify potential code and pipeline errors and, for a **Full audit**, paper–code inconsistencies. | Medium |
| **Initial synthesis** | Consolidate related observations, identify duplicates, and preserve a traceable set of potential findings for further review. | Medium |
| **Additional file review** | Re-examine files containing potential findings, with the number of additional review passes determined by the configured [Review Depth](#3-review-depth). | Medium |
| **Finding rechecks** | Verify the evidence and reasoning for each potential finding, either in batches or individually as determined by the selected review depth. | Medium |
| **Final reconciliation** | Combine the recheck evidence, resolve disagreements, and assign a final status to each potential finding. For a Full audit, also complete the final paper–code cross-checks and resolve escalated inconsistencies. | Medium |
| **Author-facing rewrite** | Rewrite the final audit records as clear, consistent entries for the findings workbook. | Low |

You can override the default reasoning effort for any stage during setup.

### Running the Audit

After configuration, the audit runs autonomously until the final spreadsheet is ready.

If a check cannot be completed because the required data, software, permissions, or computing resources are unavailable, the audit records the limitation and continues with the checks it can complete.

An interrupted audit can be resumed only if the project remains in the state recorded at the start of the audit. If any relevant files have changed, the audit must be restarted.

### Outputs

All outputs are saved in `audit/`. The main output is `audit/code_review.xlsx`, with two sheets for every audit and an additional sheet for Full audits.

| Sheet            | Contents                                                                     | Availability     |
| ---------------- | ---------------------------------------------------------------------------- | ---------------- |
| **Overview**     | A summary of the audit scope, findings, and key limitations.                 | All audits       |
| **Code Errors**  | Potential source-code errors, pipeline problems, and reproducibility issues. | All audits       |
| **Paper Claims** | Potential inconsistencies between the paper and the code.                    | Full audits only |

The `audit/` directory also contains supporting files that record the audit’s progress, rechecks, and evidence. After the audit is complete, these files can be used to inspect the evidence behind individual findings and trace how those findings were reviewed and verified. They also provide the information needed to resume an eligible interrupted audit.

### Reviewing the Findings

When the audit is complete, Claude reports the number of findings, highlights any limitations, and provides the path to the findings workbook.

Each finding has a unique ID that can be used for targeted follow-up review. You can ask Claude to re-examine the supporting evidence, verify whether a finding is valid, or check that its description and severity are accurate.

Follow-up review is read-only by default. Claude will not change the workbook or any supporting audit files without your explicit approval.

## Methodology

The audit follows six stages:

1. **Set up and map the project**
   - Create the audit workspace and record the selected configuration.
   - For a Full audit, locate the paper and convert it to Markdown if necessary.
   - Map the project’s scripts, data inputs, dependencies, pipeline stages, and outputs, including how they connect.
2. **Plan the review**
   - Divide the codebase and pipeline into manageable review tasks.
   - For a Full audit, create a separate paper–code review plan that links each section of the paper to the code, data, and outputs needed to assess it.
3. **Perform the primary review**
   - Review the code and pipeline for potential errors that could affect correctness or reproducibility.
   - For a Full audit, also check whether the paper’s claims are consistent with the code, data, and reported outputs.
4. **Consolidate observations and revisit relevant files**
   - Consolidate related observations and mark duplicates while preserving the review trail.
   - Re-examine selected files for issues missed during the primary review. The files reviewed and the number of additional passes depend on the selected [Review Depth](#3-review-depth).
5. **Verify and reconcile potential findings**
   - Independently recheck the evidence and reasoning behind each potential finding.
   - Resolve conflicting assessments and assign a final status to each potential finding.
   - For a Full audit, compare the results of the paper–code and code and pipeline reviews, linking related findings where appropriate.
6. **Prepare the outputs**
   - Rewrite the final audit records for clarity and consistency.
   - Validate the audit records and export the findings workbook.
