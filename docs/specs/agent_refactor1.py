"""
Investigation: untracked agent*.py scripts + cvss4 changes
===========================================================

Context
-------

`git status` shows three untracked files at the repo root (`agent.py`,
`agent2.py`, `agent3.py`) alongside modifications to `cvss4/cvss_40.py` and
`tests/cvss4/test_cvss_40.py`. The user asked for an investigation of the
untracked files plus refactor suggestions and Conventional-Commit messages.
This is a report-only deliverable.

Findings
--------

1. The three `agent*.py` files are iterative drafts of one experiment

All three use `claude_agent_sdk.query()` to point an autonomous agent at this
very codebase with prompts like "Find and fix the bug in cvss4" / "Review
the failing tests in cvss4 and fix the bug". Each is a more capable rewrite
of the last:

- `agent.py` (9 lines) - bare `query()` loop, `print(message)` raw dump.
- `agent2.py` (27 lines) - filters by `AssistantMessage`/`ResultMessage`,
  prints reasoning text and tool names separately.
- `agent3.py` (55 lines) - adds `max_turns`, `max_budget_usd`,
  `effort="high"`, session-id tracking, per-`ResultMessage.subtype` handling
  (`success` / `error_max_turns` / `error_max_budget_usd`), refusal
  detection, and a top-level `try/except`.

This mirrors a convention already present in `misc/`, which holds
`cvss_calci.py` and `cvss_calci3.py` - numbered iterations of an older
calculator kept for reference/study (this repo lives under `git-study/`).

Lint findings on these files:
- `agent3.py:11` - `run_agent` trips `C901` (cyclomatic complexity 13 > 9,
  the project's configured max). The `AssistantMessage`/`ResultMessage`
  branches with nested subtype handling are the bulk of it.
- `agent3.py:1` - stray `# Python` comment (looks like a pasted-in markdown
  fence label, not meaningful in a `.py` file).
- None of the three have module docstrings or fully-annotated signatures
  (the rest of the repo is annotated in strict-basedpyright style, though
  these are scratch/study scripts rather than shipped package code).

2. The cvss4 diff is a real bug fix, plausibly produced by running these
   agents

`_eq3` (`cvss4/cvss_40.py:356-364`) was classifying confidentiality/
integrity/availability impact from the raw `VC`/`VI`/`VA` metrics via
`_v()`:

    vc, vi, va = _v(p, "VC"), _v(p, "VI"), _v(p, "VA")

...while its sibling functions `_eq4` and `_eq6` already use `_eff()` to
prefer the Modified Base metrics (`MSI`/`MSA`/`MSC`, `MVC`/`MVI`/`MVA`) when
set, per CVSS 4.0 Spec Sec 7.5. The fix changes `_eq3` to match:

    vc = _eff(p, "MVC", "VC")
    vi = _eff(p, "MVI", "VI")
    va = _eff(p, "MVA", "VA")

This is correct and consistent with the rest of the EQ-classification code
(verified `_DistSpec` entries for VC/VI/VA already declare `mod="MVC"` etc.
at `cvss4/cvss_40.py:72-74`).

The test file changes layer three things together:
- New regression coverage: `test_eq3_uses_modified_metrics` plus three new
  `test_eq3` parametrize cases that assert MVC/MVI override the base
  VC/VI/VA - these are the cases that would have caught the bug.
- A full `ruff format` pass over `test_cvss_40.py` (multi-line parametrize
  lists, dict literals, etc.) - this is most of the diff's line count but
  carries no semantic change.
- One new lint regression introduced by that reformat: `E501` at
  `tests/cvss4/test_cvss_40.py:304` (a comment line now 82 > 79 chars,
  pushed over the limit by re-indentation).

All 56 tests in `tests/cvss4/test_cvss_40.py` pass with the changes as they
stand (`uv run pytest tests/cvss4/test_cvss_40.py -q` -> `56 passed`).

`cvss4/cvss_40.py` itself is not `ruff format`-clean (its dense
one-line-per-entry `_LOOKUP`/`_DistSpec` tables are an intentional deviation
from the formatter for readability) - that's pre-existing and unrelated to
this change; `ruff format --diff` would rewrite ~150 lines of lookup tables
that nobody touched, so it should NOT be run on this file.

Suggested refactors
-------------------

1. Fix `agent3.py`'s complexity (C901) - extract the per-message-type
   printing into two small helpers, e.g. `_print_assistant_message(msg)` and
   `_print_result_message(msg)`, called from the `async for` loop. This drops
   `run_agent` below the complexity threshold without changing behavior.
2. Drop the stray `# Python` line at the top of `agent3.py`.
3. Relocate all three scripts into `misc/` (per the user's preference),
   following the existing `cvss_calci.py`/`cvss_calci3.py` precedent for
   keeping numbered learning iterations out of the project root - e.g.
   `misc/agent.py`, `misc/agent2.py`, `misc/agent3.py`, or grouped under a
   subdirectory such as `misc/agent_sdk/` if the user wants them visually
   separated from the older calculator scripts.
4. Fix the new `E501` at `tests/cvss4/test_cvss_40.py:304` - wrap or shorten
   the `# CVE-2024-6387 (regreSSHion OpenSSH ...)` comment so the line fits
   in 79 columns, e.g. split across two comment lines.

Suggested commit strategy & Conventional Commit messages
---------------------------------------------------------

Two logically separate concerns are mixed in the working tree; splitting
them keeps history reviewable.

Commit 1 - the real bug fix (cvss4/cvss_40.py + tests/cvss4/test_cvss_40.py):

    fix(cvss4): use effective VC/VI/VA values when classifying EQ3

    _eq3 read the raw VC/VI/VA metrics instead of preferring the Modified
    Base metrics (MVC/MVI/MVA) via _eff(), unlike _eq4 and _eq6 (Spec
    Sec 7.5). Vectors that set MVC/MVI/MVA were scored as if those
    modifiers were absent. Add test_eq3_uses_modified_metrics plus
    MVC/MVI override cases in test_eq3 as regression coverage.

(Note: after fixing the E501 at line 304 and re-running `ruff format` on
just the test file, this commit's diff to `test_cvss_40.py` will still
include the formatter's whitespace/wrapping changes - mention that in the
body if you want the history to explain the noise, or run `ruff format` as
a documented prerequisite step.)

Commit 2 - relocate + clean up the study scripts:

    refactor(misc): move claude_agent_sdk experiment scripts into misc/

    agent.py/agent2.py/agent3.py are three iterative drafts exploring how
    to drive an autonomous agent against this codebase
    (find-and-fix-the-bug prompts of increasing sophistication). Move them
    next to the existing numbered iterations in misc/ (cvss_calci.py,
    cvss_calci3.py) to keep the project root focused on the shipped
    packages. Extract per-message-type printing helpers in agent3.py to
    satisfy the C901 complexity limit, and drop a stray leftover
    "# Python" comment line.

Verification
------------

- `uv run pytest tests/cvss4/test_cvss_40.py -q` - confirms the fix + new
  regression tests pass (56 passed, already verified).
- `uv run ruff check cvss4/cvss_40.py tests/cvss4/test_cvss_40.py
  misc/agent*.py` - confirms lint is clean after the E501 fix and the
  agent3.py complexity refactor (currently reports C901 on agent3.py:11
  and E501 on test_cvss_40.py:304).
- `make typecheck` - sanity check that strict basedpyright still passes
  (the moved scripts are scratch code, but worth a glance if
  type-annotated).
"""
