# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.3.4] — 2026-06-10

### Fixed

- `cvss4/cvss_40.py`: `_eq3` now uses effective `MVC`/`MVI`/`MVA` (via
  `_eff()`) instead of raw `VC`/`VI`/`VA` when classifying EQ3, matching
  `_eq4`/`_eq6` (Spec §7.5). Vectors setting `MVC`/`MVI`/`MVA` were
  previously scored as if those modifiers were absent. Added
  `test_eq3_uses_modified_metrics` plus MVC/MVI override cases.
- `tests/cvss2/test_cli.py`: removed unused `_fn_d` stub tripping
  basedpyright's `reportUnusedFunction`.
- `misc/agent2.py`, `misc/agent3.py`: replaced `hasattr` checks with
  `isinstance` type guards against `TextBlock`/`ToolUseBlock`/
  `ServerToolUseBlock` so basedpyright can narrow `ContentBlock`.

### Changed

- `cvss2/cvss_base.py`: removed alias `vulnerability_vector` properties
  from the `CVSS` ABC.
- `cvss2/cvss_output.py`: inlined single-use nested functions in
  `display_score`.
- `cvss4/cvss_40.py`: extracted `_metrics_from_defs` helper in
  `CommonVulnerabilityScore40`; `all_metrics()` added to
  `cvss4/vulnerability_40.py` (mirroring `cvss2/vulnerability.py`) and
  used in `_metrics`, replacing a four-source list concatenation.
- `cvss4/vulnerability_40.py`: replaced `_allowed()` plus four
  intermediate dicts with a single comprehension building
  `_ALL_ALLOWED`.
- `cvss2/cvss_handlers.py`: dropped the redundant `all_fns` parameter
  from `_accumulate_groups`.
- `misc/`: relocated the `claude_agent_sdk` experiment scripts
  (`agent.py`, `agent2.py`, `agent3.py`) into `misc/`, alongside the
  existing numbered learning iterations.
- `claude-agent-sdk` moved from `project.dependencies` into a new
  `sdk-agents` dependency-group (`pyproject.toml`); the published
  `cvss`/`cvss2`/`cvss4` packages keep `dependencies = []`.
- Dev/CI interpreter moved to Python 3.14 (`.python-version`,
  `basedpyright.pythonVersion`); the project's minimum supported
  version (`requires-python >=3.12`) is unchanged.

### Documentation

- Documented the `uv` dependency-management workflow (`uv add`/
  `uv remove`/`uv lock`/`uv sync`, dependency groups) in `README.md` and
  `CLAUDE.md`.
- Split the per-package architecture write-ups out of the root
  `CLAUDE.md` into `cvss2/CLAUDE.md` and `cvss4/CLAUDE.md` (loaded
  on-demand by Claude Code); added `.claude/rules/markdown-style.md`
  (95-character line-wrap rule for `**/*.md`).

---

## [2.3.3] — 2026-05-14

### Changed

- `cvss2/cvss_types.py`: removed the unused `CVSSResult` Protocol and its
  now-orphaned `runtime_checkable` / `Metric` imports. The `CVSS` ABC already
  provides the same interface; the Protocol was never imported anywhere.
- `cvss2/cvss_210.py`: extracted `_metrics_for(keys)` and `_vector_for(keys)`
  private helpers in `CommonVulnerabilityScore`; replaced six identical-pattern
  method bodies with one-line calls.
- `cvss4/cvss_40.py`: replaced five single-line `_dist_eqX()` wrapper methods
  with a single `_dist(mv, specs)` method; call sites in `base_score` updated to
  `lambda mv: self._dist(mv, _EQX_SPECS)`.

---

## [2.3.2] — 2026-05-14

### Fixed

- Corrected long-standing "ENIRONMENTAL" → "ENVIRONMENTAL" spelling in
  `cvss2` verbose output headers and use-case fixture.

### Changed

- `cvss/output.py` extended with shared output utilities: `print_metric_group`,
  `print_separator`, and `qualitative_rating` (moved from `cvss4`).
- `cvss2/cvss_output.py`: `_group_header(name)` and `_footer_labels(name)` helpers
  replace six hard-coded verbose header literals.
- `cvss4/cvss_output.py`: `_render_base_only` extracted from `format_output`
  to make verbose/non-verbose dispatch explicit.
- Both `format_output` implementations simplified to 2-line dispatchers via
  the shared `capture_output` helper.

### Added

- End-to-end `format_output` tests for known scoring vectors in both packages
  (3 cvss2 vectors, 2 cvss4 vectors).
- `tests/cvss/test_output.py` — direct unit tests for shared output utilities.

---

## [2.3.1] — 2026-05-14

### Added

- `_show_flags` in `cvss2/cvss_output.py` now has a direct parametrized unit
  test covering all six flag combinations (7 new test cases).
- `--vulnerability` help string in `cvss4` now documents that absent or `X`
  Exploit Maturity (E) defaults to Attacked (A) for scoring.

### Changed

- `render_output` renamed to `format_output(cvs, clarg) -> str` in both
  `cvss2/cvss_output.py` and `cvss4/cvss_output.py`; `main()` writes the
  returned string to `sys.stdout`. Tests now assert on the return value
  directly — no `capsys` capture needed in cvss4.
- `_EQLevels` promoted to public `EQLevels` in `cvss4/cvss_40.py`;
  `CVSS40Result.macro_vector` Protocol declaration updated to `EQLevels`
  so callers get named `.eq1`–`.eq6` access instead of positional indexing.

---

## [2.3.0] — 2026-05-14

### Added

- Restructured into three packages: `cvss/` (shared internals), `cvss2/` (CVSS v2.10
  CLI), `cvss4/` (CVSS v4.0 CLI). Both CLI packages install from a single `cvss` wheel.
- `cvss/` shared package: `Metric`, `MetricValue`, `MetricValueDef`, `MetricDefinition`,
  `InvalidVectorError`, `exit_with_error` consolidated; both CLI packages import from
  `cvss.*` using absolute imports.
- CVSS v4.0 verbose tabular output mode (`-v` / `--verbose`): all four metric groups
  in aligned tables plus MacroVector EQ levels, score label, severity, and vector.
- CVSS v4.0 score label prefix in output: CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE
  depending on which optional metric groups are set.
- `macro_vector` property on `CommonVulnerabilityScore40` returning `_EQLevels`
  NamedTuple of the six EQ level integers; declared in `CVSS40Result` Protocol.

### Changed

- `--cvss-version` choices simplified from `2.10` / `4.0` to `v2` / `v4`.
- `InvalidBaseVectorError` renamed to `InvalidVectorError` in cvss2 for symmetry
  with cvss4.
- `vulnerability_40` accessor methods: `_40` suffix dropped
  (`base_metrics_40` → `base_metrics`, etc.).

### Removed

- Monolithic `cvss` package replaced by the three-package structure.
- Stale `# VERSION: 1.20.1` file-level header comments.

---

## [2.2.0] — 2026-05-12

### Added

- Full CVSS v4.0 support: metric definitions for all four groups (Base,
  Threat, Environmental, Supplemental), vector parser with
  validate-on-construction, MacroVector lookup table (270 entries) and
  Equivalence-Set interpolation scoring (Spec §7–§8).
- CLI: auto-detection of v4.0 from `CVSS:4.0/` prefix; `--cvss-version`
  flag for explicit version selection in interactive mode.
- Output: qualitative severity rating (None / Low / Medium / High / Critical)
  for CVSS v4.0 scores.
- Type protocols: `CVSS40Result(CVSSResult, Protocol)` sub-protocol covering
  `threat_metrics`, `environmental_metrics`, `supplemental_metrics`; both
  `CVSSResult` and `CVSS40Result` are `@runtime_checkable`.

### Fixed

- Removed unused `clarg` parameter from `_render_v40`.

### Changed

- `VulnerabilityVector40` validates on construction (no chaining API).
- v4.0 scoring refactored to module-level pure functions: `_eq1`–`_eq6`,
  `_eq_levels`, `_dist_from_specs`, `_find_dist`, `_eq_contrib`,
  `_eq3eq6_contrib`; `_DistSpec` dataclass replaces per-method distance
  computation; `_EQLevels` NamedTuple gives named EQ level access.
- `_metrics` lazy-initialised via `functools.cached_property`.
- `render_output` dispatches via `isinstance(cvs, CVSS40Result)` instead of
  a version-string check.
- Handlers: `_cvs_from_vector` deduplicates v4.0/v2.10 routing;
  `_accumulate_groups` unifies interactive metric reading; dict-based reading
  for v4.0 interactive mode.
- `_EQ5_MAX` derived from `THREAT40_DEFINITIONS` rather than hardcoded.
- Tests: 75 → 144 (+69); new `tests/test_cvss_40.py` with parsing, EQ
  boundary conditions, 15 spec scoring examples, and protocol checks.
- README: v4.0 usage examples, Architecture section, Status update.

---

## [2.1.0] — 2026-05-10

### Added

- Full type annotations verified by basedpyright strict mode.
- pytest-based test suite replacing shell-script runners; test count 25 → 75.
- `ScoreDisplayData`, `ScoreEntry`, `CvssArgs` data types; `MetricDefinition`
  and `MetricValueDef` as frozen dataclasses (single source of truth for
  metric weights and descriptions).

### Changed

- Restructured into single-responsibility modules: `cvss_parser`,
  `cvss_handlers`, `cvss_input`, `cvss_output`, `cvss_types`.
- DRY refactors: `_show_flags`, `ScoreEntry`, `ScoreDisplayData` extracted.
- Module rename: `cvss_interactive` → `cvss_prompt` → `cvss_input`.
- README converted from RST to Markdown with Code Structure and Dev Flow
  sections.

---

## [2.0.0] — 2026-05-08

### Added

- Full type annotations, verified by basedpyright strict mode.
- pytest test suite (25 use-case tests).

### Changed

- Modernised packaging: `uv` + `pyproject.toml` (hatchling build backend).
- Linter/formatter switched from flake8/pep8 to ruff.
- Dropped Python 2 support; requires Python ≥ 3.10.
