# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
