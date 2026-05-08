# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make install      # create .venv, install all deps (run once after cloning)
make test         # run full test suite (pytest --doctest-modules)
make lint         # check style (ruff)
make format       # auto-fix style (ruff)
make typecheck    # static type check (basedpyright)
make example      # run example suite
make build        # build wheel + sdist into dist/
make clean        # remove build artefacts
```

Run a single test file:
```bash
uv run pytest tests/test_cvss_210.py
```

Run a single test by name:
```bash
uv run pytest tests/test_cli.py::test_base_score
```

Doctests are collected automatically from all `cvss/` modules via `--doctest-modules` in `pyproject.toml`.

## Architecture

This is a CLI tool (`cvss` entry point → `cvss/cvss.py:main`) that computes CVSS v2.10 scores.

**Data layer** (`cvss/vulnerability.py`):
- `MetricValueDef` / `MetricDefinition` are frozen dataclasses — the single source of truth for all metric names, abbreviations, weights and descriptions.
- `BASE_DEFINITIONS`, `TEMPORAL_DEFINITIONS`, `ENVIRONMENTAL_DEFINITIONS` are module-level tuples; all validation dicts and key lists are *derived* from them, never duplicated.
- `VulnerabilityVector` parses and validates a slash-separated vector string (e.g. `AV:N/AC:L/Au:N/C:C/I:C/A:C`). Its `valid()` / `complete()` chain raises `InvalidBaseVectorError` or `ValueError` on bad input.
- `cvs_factory()` is the canonical way to build a `CVSS` instance from a list of selected abbreviation strings.

**Scoring layer** (`cvss/cvss_base.py`, `cvss/cvss_210.py`):
- `CVSS` (abstract, `cvss_base.py`) is a template-method ABC. It provides concrete `base_score`, `temporal_score`, `environmental_score` properties that call abstract hooks (`base_fcn`, `temporal_fcn`, `environmental_fcn`, `impact`, `exploitability`, …).
- `CommonVulnerabilityScore` (`cvss_210.py`) is the only concrete implementation. It holds metrics in a `dict[str, Metric]` keyed by abbreviation. The key lists (`_BASE_KEYS`, `_TEMPORAL_KEYS`, `_ENV_KEYS`) are derived from the `*_DEFINITIONS` tuples.

**Metric layer** (`cvss/metric.py`, `cvss/metric_value.py`):
- `Metric` wraps a named set of `MetricValue` options and tracks the currently selected one. `float(metric)` returns the weight of the selected value.

**CLI layer** (`cvss/cvss.py`, `cvss/cvss_interactive.py`, `cvss/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) is a `TypedDict` mirroring the argparse `Namespace` — cast once in `main()`, then passed everywhere typed.
- `ScoreEntry` is a `NamedTuple(name, value, vector)` used by `generate_output`.
- Three entry paths in `process_cmd_line`: `process_cmd_line_interactive` (reads from stdin), `process_cmd_line_base` (vector from CLI arg), `process_cmd_line_vulnerability` (full vector via `--vulnerability`).
- Display helpers (`generate_output`, `generate_verbose_output`, `display_score`, `ScoreDisplayData`) live in `cvss_interactive.py`.

**Tests** (`tests/`):
- `test_usecases.py` drives the shell-script use-case fixtures (`tests/test_uc*.txt`).
- `tests/test_uc02_out.txt` is the fixture for interactive output including the `###| |###` trace in `select_metric_value` — changing that line requires updating this fixture.

## Tooling

- Python 3.12, managed by `uv`. Lock file: `uv.lock`.
- Linter/formatter: `ruff` (line length 79, rules E/F/W/C90/N, max complexity 9).
- Type checker: `basedpyright` in strict mode. All public APIs must be fully annotated.
- `basedpyright` settings are in `pyproject.toml`; `reportAny` and `reportExplicitAny` are warnings, not errors — but avoid `Any` unless unavoidable.
