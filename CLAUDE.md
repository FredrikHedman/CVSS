# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

Doctests are collected automatically from all `cvss/`, `cvss2/`, and `cvss4/` modules via `--doctest-modules` in `pyproject.toml`.

## Architecture

The repo ships two standalone CLI tools, each in its own package:

- **`cvss2`** (`cvss2/`) — CVSS v2.10 calculator with interactive mode
- **`cvss4`** (`cvss4/`) — CVSS v4.0 calculator, no interactive mode

All three packages are shipped together. `cvss/` holds the shared internals that both CLI packages import from:

- `cvss/metric_value.py` — `MetricValue` frozen dataclass
- `cvss/metric.py` — `Metric` class (wraps a named set of `MetricValue` options)
- `cvss/vulnerability.py` — `MetricValueDef`, `MetricDefinition` frozen dataclasses; `InvalidVectorError` exception
- `cvss/cli.py` — `exit_with_error(e) -> NoReturn` shared CLI helper

Both cvss2 and cvss4 import from `cvss.*` using **absolute imports** (never relative). New shared utilities belong in `cvss/`, not duplicated across packages.

### cvss2/ architecture

**Data layer** (`cvss2/vulnerability.py`):
- Imports `MetricValueDef`, `MetricDefinition`, `InvalidVectorError` from `cvss.vulnerability`.
- `BASE_DEFINITIONS`, `TEMPORAL_DEFINITIONS`, `ENVIRONMENTAL_DEFINITIONS` are module-level tuples; validation dicts and key lists derived from them.
- `VulnerabilityVector` parses and validates vectors. `valid()` / `complete()` chain raises `InvalidVectorError` or `ValueError`.
- `cvs_factory()` builds a `CVSS` instance from selected abbreviation strings.

**Scoring layer** (`cvss2/cvss_base.py`, `cvss2/cvss_210.py`):
- `CVSS` (abstract, `cvss_base.py`) is a template-method ABC. Concrete `base_score`, `temporal_score`, `environmental_score` properties call abstract hooks.
- `CommonVulnerabilityScore` (`cvss_210.py`) is the concrete implementation. Metrics in `dict[str, Metric]` keyed by abbreviation.

**CLI layer** (`cvss2/cvss.py`, `cvss2/cvss_parser.py`, `cvss2/cvss_handlers.py`, `cvss2/cvss_input.py`, `cvss2/cvss_output.py`, `cvss2/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) is a `TypedDict` mirroring the argparse `Namespace` (8 keys, no `cvss_version`).
- `CVSSResult` protocol (`cvss_types.py`) is satisfied by `CommonVulnerabilityScore`.
- `cvss_handlers.py` contains `process_cmd_line_interactive`, `process_cmd_line_base`, `process_cmd_line_vulnerability`, `process_cmd_line`.
- `cvss_input.py`: `select_metric_value`, `read_metrics` — pure terminal I/O.
- `cvss_output.py`: `render_output(cvs: CVSS, clarg: CvssArgs)`, `display_score`, `ScoreDisplayData`.

**Tests** (`tests/cvss2/`):
- `test_usecases.py` drives the use-case fixtures (`tests/cvss2/test_uc*.txt`) via the `cvss2` binary.
- `tests/cvss2/test_uc02_out.txt` is the fixture for interactive output — changing `select_metric_value`'s `###| |###` trace requires updating it.

### cvss4/ architecture

**Data layer** (`cvss4/vulnerability_40.py`):
- Imports `MetricDefinition`, `MetricValueDef`, `InvalidVectorError` from `cvss.vulnerability`.
- `BASE40_DEFINITIONS`, `THREAT40_DEFINITIONS`, `ENVIRONMENTAL40_DEFINITIONS`, `SUPPLEMENTAL40_DEFINITIONS` — four metric groups (Spec §7.1–§7.4).
- `VulnerabilityVector40` validates and parses `CVSS:4.0/` vectors on construction. `parsed` is a `cached_property` returning `dict[str, str]` (absent metrics default to `"X"`).
- `_ALL_ALLOWED` — validation dict derived from all four definition groups.

**Scoring layer** (`cvss4/cvss_40.py`):
- `CommonVulnerabilityScore40` — standalone class (does not inherit from the v2.10 CVSS ABC). Uses MacroVector lookup table (270 entries) + EQ-set interpolation (Spec §7–§8).
- `macro_vector` property — returns `_EQLevels` NamedTuple of the six EQ level integers.
- `_eq1`–`_eq6` — module-level pure EQ classification functions.
- `_DistSpec` dataclass — per-EQ distance configuration.
- `_EQLevels` NamedTuple — named EQ level access.
- `_metrics` — `cached_property` (lazy; not triggered by `base_score`).

**CLI layer** (`cvss4/cvss.py`, `cvss4/cvss_parser.py`, `cvss4/cvss_handlers.py`, `cvss4/cvss_output.py`, `cvss4/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) — 4 keys: `verbose`, `base`, `vector`, `vulnerability`. No interactive/temporal/environmental/all.
- `CVSS40Result` protocol — `@runtime_checkable`; satisfied by `CommonVulnerabilityScore40`.
- `cvss4` has **no interactive mode**. Only `--base <vector>` and `--vulnerability <vector>`.
- `cvss_output.py`: `render_output(cvs: CVSS40Result)`, `qualitative_rating(score)`.

**Tests** (`tests/cvss4/`):
- `test_cvss_40.py` — unit and scoring tests (15 spec examples, EQ boundary conditions, protocol checks).
- `test_cli.py` — integration tests via `cvss4` binary.
- `test_display.py` — output function tests.

## Tooling

- Dev/CI interpreter: Python 3.14, managed by `uv`. Lock file: `uv.lock`; version pinned in `.python-version`. (The project's minimum supported version is `>=3.12`, set via `requires-python` in `pyproject.toml`.)
- `[dependency-groups] dev` in `pyproject.toml` holds dev-only deps (basedpyright, pytest, ruff).
- Use `uv add <pkg>` / `uv add --group dev <pkg>` / `uv remove <pkg>` to change deps — these update `pyproject.toml`, `uv.lock`, and `.venv` together.
- If `pyproject.toml` is edited by hand, run `make lock` then `make install` to regenerate `uv.lock` and resync `.venv`.
- Linter/formatter: `ruff` (line length 79, rules E/F/W/C90/N, max complexity 9).
- Type checker: `basedpyright` in strict mode. All public APIs must be fully annotated.
- `basedpyright` settings are in `pyproject.toml`; `reportAny` and `reportExplicitAny` are warnings, not errors — but avoid `Any` unless unavoidable.
