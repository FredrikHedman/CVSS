# CVSS Calculator

CVSS calculator for [CVSS version 2.10](http://www.first.org/cvss/cvss-guide.html).

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/):

    git clone git@github.com:FredrikHedman/CVSS.git
    cd CVSS
    make install
    uv run cvss --help

`make install` creates a `.venv` virtualenv, installs all runtime and
development dependencies, and ensures `uv.lock` is in sync with
`pyproject.toml`.

## Usage

    cvss [-v] --interactive --all
    cvss [-v] --interactive [--temporal] --base [<vector>]
    cvss [-v] --interactive [--environmental] --temporal --base [<vector>]
    cvss [-v] --base <vector>
    cvss [-v] --vulnerability <vector>
    cvss (--help | --version)

## Status

| Item | Detail |
|------|--------|
| Version | 2.0.0 |
| Python | ≥ 3.12 |
| License | MIT |
| Type-checked | basedpyright strict |
| Linter | ruff |

**What's new in 2.0.0**: Modernised packaging (uv + pyproject.toml),
replaced flake8/pep8 with ruff, replaced shell-script test runners with
pytest, dropped Python 2 support, full type annotations, restructured into
single-responsibility modules.

## Code Structure

| Module | Responsibility |
|--------|----------------|
| `cvss/cvss.py` | Entry point — `main()` only |
| `cvss/cvss_parser.py` | Argument parsing and flag validation |
| `cvss/cvss_handlers.py` | Mode handlers (`--base`, `--vulnerability`, `--interactive`) and dispatch |
| `cvss/cvss_input.py` | Interactive terminal input (`select_metric_value`, `read_metrics`) |
| `cvss/cvss_output.py` | Score output formatting (`render_output`, `generate_output`, `generate_verbose_output`) |
| `cvss/cvss_types.py` | Shared types (`CvssArgs`, `ScoreEntry`) |
| `cvss/cvss_base.py` | Abstract scoring base class (`CVSS`) |
| `cvss/cvss_210.py` | Concrete CVSS v2.10 implementation |
| `cvss/vulnerability.py` | Metric definitions, vector parsing, factory |
| `cvss/metric.py` | `Metric` class |
| `cvss/metric_value.py` | `MetricValue` class |

## Development Flow

    make install      # create .venv, install all deps
    make test         # pytest (includes doctests)
    make lint         # ruff check
    make format       # ruff format
    make typecheck    # basedpyright
    make example      # run example suite
    make build        # wheel + sdist into dist/
    make clean        # remove build artefacts

To run a single test file:

    uv run pytest tests/test_cli.py

To run a single test by name:

    uv run pytest tests/test_cli.py::test_base_score

## Developers

Fredrik Hedman <fredrik.hedman@noruna.se>
