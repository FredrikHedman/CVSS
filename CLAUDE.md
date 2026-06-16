# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

These project instructions override any conflicting user-level defaults.
**Tradeoff:** these guidelines bias toward caution over speed; for
trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If
yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix a failing test" → make the minimal source change to pass it; never
  edit the test to force it green unless the test is demonstrably wrong —
  say so explicitly if you do.
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria
("make it work") require constant clarification.

## Commands

```bash
make install      # sync .venv with uv.lock, incl. dev deps (run once after cloning)
make lock         # regenerate uv.lock from pyproject.toml (run after editing deps)
make test         # run full test suite (pytest --doctest-modules)
make lint         # check style (ruff)
make format       # auto-fix style (ruff)
make typecheck    # static type check (basedpyright)
make example      # run example suite (cvss2)
make build        # build wheel + sdist into dist/
make clean        # remove build artefacts
```

Run a single test file:
```bash
uv run pytest tests/cvss2/test_usecases.py
uv run pytest tests/cvss4/test_cvss_40.py
```

Run a single test by name:
```bash
uv run pytest tests/cvss2/test_cli.py::test_base_flag_parsed
uv run pytest tests/cvss4/test_cli.py::test_vulnerability_vector
```

Doctests are collected automatically from all `cvss/`, `cvss2/`, and
`cvss4/` modules via `--doctest-modules` in `pyproject.toml`.

## Architecture

The repo ships two standalone CLI tools, each in its own package:

- **`cvss2`** (`cvss2/`) — CVSS v2.10 calculator with interactive mode.
  See `cvss2/CLAUDE.md` for module-level details.
- **`cvss4`** (`cvss4/`) — CVSS v4.0 calculator, no interactive mode.
  See `cvss4/CLAUDE.md` for module-level details.

All three packages are shipped together. `cvss/` holds the shared
internals that both CLI packages import from:

- `cvss/metric_value.py` — `MetricValue` frozen dataclass
- `cvss/metric.py` — `Metric` class (wraps a named set of `MetricValue`
  options)
- `cvss/vulnerability.py` — `MetricValueDef`, `MetricDefinition` frozen
  dataclasses; `InvalidVectorError` exception
- `cvss/cli.py` — `exit_with_error(e) -> NoReturn` shared CLI helper
- `cvss/output.py` — `capture_output`, `print_metric_group`,
  `print_separator`, `qualitative_rating`

Both cvss2 and cvss4 import from `cvss.*` using **absolute imports**
(never relative). New shared utilities belong in `cvss/`, not duplicated
across packages.

Tests live in `tests/` and mirror the package layout (`tests/cvss2/`
mirrors `cvss2/`, etc.). `misc/` holds restricted agent experiments and
is not covered by this convention.

## Tooling

- Dev/CI interpreter: Python 3.14, managed by `uv`. Lock file: `uv.lock`;
  version pinned in `.python-version`. (The project's minimum supported
  version is `>=3.12`, set via `requires-python` in `pyproject.toml`.)
- `[dependency-groups] dev` in `pyproject.toml` holds dev-only deps
  (basedpyright, pytest, ruff).
- `[dependency-groups] sdk-agents` holds `claude-agent-sdk`, used only by
  the experiment scripts in `misc/agent*.py`. The shipped
  `cvss`/`cvss2`/`cvss4` packages keep `dependencies = []`.
- Use `uv add <pkg>` / `uv add --group dev <pkg>` / `uv remove <pkg>` to
  change deps — these update `pyproject.toml`, `uv.lock`, and `.venv`
  together.
- If `pyproject.toml` is edited by hand, run `make lock` then
  `make install` to regenerate `uv.lock` and resync `.venv`.
- Linter/formatter: `ruff` (line length 79, rules E/F/W/C90/N, max
  complexity 9).
- Type checker: `basedpyright` in strict mode. All public APIs must be
  fully annotated.
- `basedpyright` settings are in `pyproject.toml`; `reportAny` and
  `reportExplicitAny` are warnings, not errors — but avoid `Any` unless
  unavoidable.
