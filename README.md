# CVSS Calculator

CVSS calculator supporting [CVSS v4.0](https://www.first.org/cvss/v4-0/) (default)
and [CVSS v2.10](https://www.first.org/cvss/v2/guide).

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

    # CVSS v4.0 (auto-detected from CVSS:4.0/ prefix)
    cvss --vulnerability "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    # CVSS v2.10 (auto-detected — no CVSS:4.0/ prefix)
    cvss --vulnerability "AV:N/AC:L/Au:N/C:C/I:C/A:C"

    # Explicit version selection for interactive mode
    cvss --cvss-version 2.10 --interactive --base

## Examples

### CVSS v4.0

**Log4Shell (CVE-2021-44228) — Exploit Maturity: Attacked**

```bash
$ cvss --vulnerability "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"

CVSS v4.0 Score = 9.3
Severity = Critical
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A
```

**CVE-2020-3549 (Cisco Firepower) — base metrics only**

Absent Exploit Maturity (E) defaults to Attacked for scoring (Spec §7.4).

```bash
$ cvss --vulnerability "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

CVSS v4.0 Score = 7.7
Severity = High
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

**Using `--base` directly**

```bash
$ cvss --base "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

CVSS v4.0 Score = 9.3
Severity = Critical
CVSS v4.0 Vulnerability Vector = CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

### CVSS v2.10

**`--vulnerability` — outputs Base, Temporal, and Environmental scores**

```bash
$ cvss --vulnerability "AV:N/AC:L/Au:N/C:C/I:C/A:C"

Base Score = 10.0
Base Vulnerability Vector = AV:N/AC:L/Au:N/C:C/I:C/A:C
Temporal Score = 10.0
Temporal Vulnerability Vector = E:ND/RL:ND/RC:ND
Environmental Score = 10.0
Environmental Vulnerability Vector = CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND
```

**`--base` — outputs Base score only**

```bash
$ cvss --base "AV:N/AC:M/Au:S/C:C/I:P/A:C"

Base Score = 8.2
Base Vulnerability Vector = AV:N/AC:M/Au:S/C:C/I:P/A:C
```

**`--verbose` — tabular output with per-metric weights**

```bash
$ cvss -v --vulnerability "AV:N/AC:L/Au:N/C:C/I:C/A:C"

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

| Item          | Detail                  |
|---------------|-------------------------|
| Version       | 2.1.0                   |
| CVSS versions | 2.10, 4.0 (default)     |
| Python        | ≥ 3.12                  |
| License       | MIT                     |
| Type-checked  | basedpyright strict     |
| Linter        | ruff                    |

**What's new in 2.0.0**: Modernised packaging (uv + pyproject.toml),
replaced flake8/pep8 with ruff, replaced shell-script test runners with
pytest, dropped Python 2 support, full type annotations, restructured into
single-responsibility modules.

## Code Structure

| Module                      | Responsibility                                                           |
|-----------------------------|--------------------------------------------------------------------------|
| `cvss/cvss.py`              | Entry point — `main()` only                                              |
| `cvss/cvss_parser.py`       | Argument parsing and flag validation                                     |
| `cvss/cvss_handlers.py`     | Mode handlers (`--base`, `--vulnerability`, `--interactive`) and dispatch |
| `cvss/cvss_input.py`        | Interactive terminal input (`select_metric_value`, `read_metrics`)       |
| `cvss/cvss_output.py`       | Score output; `render_output`, `qualitative_rating`, `ScoreDisplayData`  |
| `cvss/cvss_types.py`        | Shared types (`CvssArgs`, `CVSSResult`, `ScoreEntry`)                    |
| `cvss/cvss_base.py`         | Abstract scoring base class (`CVSS`, v2.10 only)                         |
| `cvss/cvss_210.py`          | Concrete CVSS v2.10 implementation                                       |
| `cvss/cvss_40.py`           | Standalone CVSS v4.0 scorer (`CommonVulnerabilityScore40`)               |
| `cvss/vulnerability.py`     | CVSS v2.10 metric definitions, vector parsing, factory                   |
| `cvss/vulnerability_40.py`  | CVSS v4.0 metric definitions and `VulnerabilityVector40`                 |
| `cvss/metric.py`            | `Metric` class                                                           |
| `cvss/metric_value.py`      | `MetricValue` class                                                      |

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

## Architecture: CVSS v4.0 Scoring

### Why v4.0 does not reuse the v2.10 CVSS abstract base class

CVSS v2.10 scoring uses closed-form formulas with numeric metric weights
(Spec v2.10 §3). The `CVSS` abstract base class (`cvss_base.py`) encodes this
structure via abstract methods `base_fcn`, `impact`, `exploitability`, and
related hooks.

CVSS v4.0 replaces formulas with a **MacroVector lookup table** approach
(Spec v4.0 §7–§8). There are no numeric metric weights; instead vectors are
classified into six Equivalence Sets (EQ1–EQ6) and the score is read from a
270-entry table, then refined by interpolation. The formula-based abstract
methods of the v2.10 ABC have no meaningful v4.0 equivalent. Forcing v4.0
into the existing ABC would require stub implementations with no semantic
content, which is misleading and error-prone.

**Decision**: `CommonVulnerabilityScore40` (`cvss/cvss_40.py`) is a standalone
class implementing the `CVSSResult` Protocol (`cvss_types.py`). Both
`CommonVulnerabilityScore` (v2.10) and `CommonVulnerabilityScore40` (v4.0)
satisfy this protocol; the rest of the codebase works through the protocol.

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
An interpolation step (Spec §8.3, references `cvss_lookup.js` in the FIRST
calculator) adjusts the score within the MacroVector based on how far the
current vector is from the most-severe vector in its class. EQ3 and EQ6 are
treated as a combined dimension in the interpolation.

Lookup table and `MAX_COMPOSED`/`MAX_SEVERITY` constants are sourced from the
[RedHatProductSecurity/cvss](https://github.com/RedHatProductSecurity/cvss)
reference implementation, which mirrors the
[FIRST calculator](https://www.first.org/cvss/calculator/4.0).

### Qualitative severity ratings (Spec §9)

| Rating   | Score range |
|----------|-------------|
| None     | 0.0         |
| Low      | 0.1–3.9     |
| Medium   | 4.0–6.9     |
| High     | 7.0–8.9     |
| Critical | 9.0–10.0    |

Use `qualitative_rating(score)` from `cvss_output.py`.

### Vector format (Spec §6)

All v4.0 vectors begin with the `CVSS:4.0/` prefix. All 11 base metrics are
mandatory and must appear in a fixed order. Optional metric groups (Threat,
Environmental, Supplemental) default to `X` (Not Defined) when absent. The
CLI auto-detects the version from this prefix; `--cvss-version` applies only
to `--interactive` mode.

## Developers

Fredrik Hedman <fredrik.hedman@noruna.se>
