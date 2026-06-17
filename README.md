# CVSS Calculator

Two standalone CVSS calculators:

- **`cvss2`** — [CVSS v2.10](https://www.first.org/cvss/v2/guide) with full interactive mode
- **`cvss4`** — [CVSS v4.0](https://www.first.org/cvss/v4-0/) (no interactive mode)

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/):

    git clone git@github.com:FredrikHedman/CVSS.git
    cd CVSS
    make install
    uv run cvss2 --help
    uv run cvss4 --help

`make install` creates a `.venv` virtualenv, installs all runtime and
development dependencies, and ensures `uv.lock` is in sync with
`pyproject.toml`.

### Updating dependencies

    uv add <package>             # add a runtime dependency
    uv add --group dev <package> # add a dev-only dependency
    uv remove <package>          # remove a dependency

`uv add`/`uv remove` update `pyproject.toml`, `uv.lock`, and `.venv`
together. If you edit `pyproject.toml` by hand instead, run
`make lock` (regenerates `uv.lock`) followed by `make install` (resyncs
`.venv`). After `git pull`, run `make install` to resync `.venv` if
`uv.lock` changed.

`.python-version` pins the Python version (3.14) that `uv sync`
provisions for `.venv`.

### Dependency groups

The published `cvss`/`cvss2`/`cvss4` packages have zero runtime
dependencies (`dependencies = []`). `[dependency-groups]` in
`pyproject.toml` holds dev-only tooling:

- `dev` — `basedpyright`, `pytest`, `ruff` (lint/type-check/test tooling)
- `sdk-agents` — `claude-agent-sdk`, used only by the experiment scripts
  in `misc/agent*.py`

`make install` (`uv sync --all-groups`) installs all groups. To run a
`misc/` agent script: `uv run python misc/agent3.py`.

## Usage

### cvss2 (CVSS v2.10)

    cvss2 [-v] --interactive --all
    cvss2 [-v] --interactive [--temporal] --base [<vector>]
    cvss2 [-v] --interactive [--environmental] --temporal --base [<vector>]
    cvss2 [-v] --base <vector>
    cvss2 [-v] --vulnerability <vector>
    cvss2 (--help | --version)

### cvss4 (CVSS v4.0)

    cvss4 [-v] --base <vector>
    cvss4 [-v] --vulnerability <vector>
    cvss4 (--help | --version)

    # CVSS v4.0 vectors begin with the CVSS:4.0/ prefix
    cvss4 --vulnerability "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

## Examples

### CVSS v4.0

**Log4Shell (CVE-2021-44228) — Exploit Maturity: Attacked**

```bash
$ cvss4 --vulnerability "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"

CVSS v4.0 Score = 9.3
Severity = Critical
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A
```

**CVE-2020-3549 (Cisco Firepower) — base metrics only**

Absent Exploit Maturity (E) defaults to Attacked for scoring (Spec §7.4).

```bash
$ cvss4 --vulnerability "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

CVSS v4.0 Score = 7.7
Severity = High
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

**Using `--base` directly**

```bash
$ cvss4 --base "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

CVSS v4.0 Score = 9.3
Severity = Critical
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

### CVSS v2.10

**`--vulnerability` — outputs Base, Temporal, and Environmental scores**

```bash
$ cvss2 --vulnerability "AV:N/AC:L/Au:N/C:C/I:C/A:C"

Base Score = 10.0
Base Vulnerability Vector = AV:N/AC:L/Au:N/C:C/I:C/A:C
Temporal Score = 10.0
Temporal Vulnerability Vector = E:ND/RL:ND/RC:ND
Environmental Score = 10.0
Environmental Vulnerability Vector = CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND
```

**`--base` — outputs Base score only**

```bash
$ cvss2 --base "AV:N/AC:M/Au:S/C:C/I:P/A:C"

Base Score = 8.2
Base Vulnerability Vector = AV:N/AC:M/Au:S/C:C/I:P/A:C
```

**`--verbose` — tabular output with per-metric weights**

```bash
$ cvss2 -v --vulnerability "AV:N/AC:L/Au:N/C:C/I:C/A:C"

=================================================================
BASE METRIC                   EVALUATION                    SCORE
=================================================================
Access Vector                 Network                        1.00
Access Complexity             Low                            0.71
Authentication                None                           0.70
Confidentiality Impact        Complete                       0.66
Integrity Impact              Complete                       0.66
Availability Impact           Complete                       0.66
=================================================================
FORMULA                                                BASE SCORE
=================================================================
Impact =                                                    10.00
Exploitability =                                            10.00
Base Score =                                                10.00
Base Vulnerability Vector: AV:N/AC:L/Au:N/C:C/I:C/A:C
=================================================================
# ... temporal and environmental tables follow
```

## Status

| Item           | cvss2                                     | cvss4                                     |
|----------------|-------------------------------------------|-------------------------------------------|
| Version        | 2.3.5                                     | 2.3.5                                     |
| CVSS version   | 2.10                                      | 4.0                                       |
| Scoring        | Closed-form formulas (Spec §3)            | MacroVector lookup table (Spec §7–§8)     |
| Interactive    | Yes (`-i` flag)                           | No                                        |
| Python         | ≥ 3.12                                    | ≥ 3.12                                    |
| License        | MIT                                       | MIT                                       |
| Type-checked   | basedpyright strict                       | basedpyright strict                       |
| Linter         | ruff                                      | ruff                                      |
| Tests          | 94 passing                                | 87 passing                                |

## Code Structure

### cvss/ — Shared internals

| Module               | Responsibility                                                                       |
|----------------------|--------------------------------------------------------------------------------------|
| `cvss/__init__.py`   | `InvalidVectorError`, `exit_with_error(e) -> NoReturn`, `capture_output`             |

### cvss2/ — CVSS v2.10

| Module                      | Responsibility                                                               |
|-----------------------------|------------------------------------------------------------------------------|
| `cvss2/cvss.py`             | Entry point — `main()` only                                                  |
| `cvss2/cvss_parser.py`      | Argument parsing and flag validation                                         |
| `cvss2/cvss_handlers.py`    | Mode handlers (`--base`, `--vulnerability`, `--interactive`) and dispatch    |
| `cvss2/cvss_input.py`       | Interactive terminal input (`select_metric_value`, `read_metrics`)           |
| `cvss2/cvss_output.py`      | Score output; `render_output`, `ScoreDisplayData`, `display_score`           |
| `cvss2/cvss_types.py`       | Shared types (`CvssArgs`, `CVSSResult`, `ScoreEntry`)                        |
| `cvss2/cvss_base.py`        | Abstract scoring base class (`CVSS`)                                         |
| `cvss2/cvss_210.py`         | Concrete CVSS v2.10 implementation                                           |
| `cvss2/metric_value.py`     | `MetricValue` frozen dataclass (metric, value, weight, description)          |
| `cvss2/metric.py`           | `Metric` — named set of `MetricValue` options; `float(m)` returns weight     |
| `cvss2/vulnerability.py`    | `MetricValueDef`, `MetricDefinition`; metric definitions, vector parsing,    |
|                             | factory helpers                                                              |

### cvss4/ — CVSS v4.0

| Module                      | Responsibility                                                               |
|-----------------------------|------------------------------------------------------------------------------|
| `cvss4/cvss.py`             | Entry point — `main()` only                                                  |
| `cvss4/cvss_parser.py`      | Argument parsing (`--base`, `--vulnerability`, `--verbose`)                  |
| `cvss4/cvss_handlers.py`    | Handler and dispatch (no interactive mode)                                   |
| `cvss4/cvss_output.py`      | Score output; `format_output`, `qualitative_rating`                          |
| `cvss4/cvss_types.py`       | `CvssArgs`, `CVSS40Result`, `MetricDisplay` (verbose table row)              |
| `cvss4/cvss_40.py`          | Standalone CVSS v4.0 scorer (`CommonVulnerabilityScore40`); `_display_for()` |
|                             | builds `list[MetricDisplay]` for verbose output                              |
| `cvss4/vulnerability_40.py` | `_V40Value`, `_V40Def` (no weight field); metric definitions;                |
|                             | `VulnerabilityVector40`                                                      |

## Development Flow

    make install      # create .venv, install all deps
    make test         # pytest (includes doctests)
    make lint         # ruff check
    make format       # ruff format
    make typecheck    # basedpyright
    make example      # run example suite (cvss2)
    make build        # wheel + sdist into dist/
    make clean        # remove build artefacts

To run a single test file:

    uv run pytest tests/cvss2/test_usecases.py
    uv run pytest tests/cvss4/test_cvss_40.py

To run a single test by name:

    uv run pytest tests/cvss2/test_cli.py::test_base_flag_parsed
    uv run pytest tests/cvss4/test_cli.py::test_vulnerability_vector

## Architecture: CVSS v4.0 Scoring

### Why cvss4 does not reuse the v2.10 CVSS abstract base class

CVSS v2.10 scoring uses closed-form formulas with numeric metric weights
(Spec v2.10 §3). The `CVSS` abstract base class (`cvss2/cvss_base.py`) encodes
this structure via abstract methods `base_fcn`, `impact`, `exploitability`, and
related hooks.

CVSS v4.0 replaces formulas with a **MacroVector lookup table** approach
(Spec v4.0 §7–§8). There are no numeric metric weights; instead vectors are
classified into six Equivalence Sets (EQ1–EQ6) and the score is read from a
270-entry table, then refined by interpolation. Forcing v4.0 into the v2.10
ABC would require stub implementations with no semantic content.

**Decision**: `CommonVulnerabilityScore40` (`cvss4/cvss_40.py`) is a standalone
class implementing the `CVSS40Result` Protocol (`cvss4/cvss_types.py`).

### MacroVector scoring (Spec §7–§8)

A vector is mapped to six Equivalence Sets, each capturing a dimension of
severity. Level 0 is most severe.

| EQ  | Metrics           | Levels |
|-----|-------------------|--------|
| EQ1 | AV, PR, UI        | 0–2    |
| EQ2 | AC, AT            | 0–1    |
| EQ3 | VC, VI, VA        | 0–2    |
| EQ4 | SC, SI, SA        | 0–2    |
| EQ5 | E (exploit maturity) | 0–2 |
| EQ6 | CR/IR/AR vs VC/VI/VA | 0–1 |

The six EQ levels form a key into the lookup table (270 valid combinations).
An interpolation step (Spec §8.3) adjusts the score within the MacroVector
based on how far the current vector is from the most-severe vector in its
class. EQ3 and EQ6 are treated as a combined dimension in the interpolation.

### Qualitative severity ratings (Spec §9)

| Rating   | Score range |
|----------|-------------|
| None     | 0.0         |
| Low      | 0.1–3.9     |
| Medium   | 4.0–6.9     |
| High     | 7.0–8.9     |
| Critical | 9.0–10.0    |

Use `qualitative_rating(score)` from `cvss4/cvss_output.py`.

### Vector format (Spec §6)

All v4.0 vectors begin with the `CVSS:4.0/` prefix. All 11 base metrics are
mandatory and must appear in a fixed order. Optional metric groups (Threat,
Environmental, Supplemental) default to `X` (Not Defined) when absent.

## Developers

Fredrik Hedman <fredrik.hedman@noruna.se>
