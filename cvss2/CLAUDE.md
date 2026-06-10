# cvss2/ architecture

CVSS v2.10 calculator with full interactive mode. Shared internals live in
`cvss/` (see root `CLAUDE.md`); global commands and tooling are also
documented there.

**Data layer** (`cvss2/vulnerability.py`):
- Imports `MetricValueDef`, `MetricDefinition`, `InvalidVectorError` from
  `cvss.vulnerability`.
- `BASE_DEFINITIONS`, `TEMPORAL_DEFINITIONS`, `ENVIRONMENTAL_DEFINITIONS`
  are module-level tuples; validation dicts and key lists are derived from
  them.
- `VulnerabilityVector` parses and validates vectors. `valid()` /
  `complete()` chain raises `InvalidVectorError` or `ValueError`.
- `cvs_factory()` builds a `CVSS` instance from selected abbreviation
  strings.

**Scoring layer** (`cvss2/cvss_base.py`, `cvss2/cvss_210.py`):
- `CVSS` (abstract, `cvss_base.py`) is a template-method ABC. Concrete
  `base_score`, `temporal_score`, `environmental_score` properties call
  abstract hooks.
- `CommonVulnerabilityScore` (`cvss_210.py`) is the concrete
  implementation. Metrics in `dict[str, Metric]` keyed by abbreviation.

**CLI layer** (`cvss2/cvss.py`, `cvss2/cvss_parser.py`,
`cvss2/cvss_handlers.py`, `cvss2/cvss_input.py`, `cvss2/cvss_output.py`,
`cvss2/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) is a `TypedDict` mirroring the argparse
  `Namespace` (8 keys, no `cvss_version`).
- `CVSSResult` protocol (`cvss_types.py`) is satisfied by
  `CommonVulnerabilityScore`.
- `cvss_handlers.py` contains `process_cmd_line_interactive`,
  `process_cmd_line_base`, `process_cmd_line_vulnerability`,
  `process_cmd_line`.
- `cvss_input.py`: `select_metric_value`, `read_metrics` — pure terminal
  I/O.
- `cvss_output.py`: `render_output(cvs: CVSS, clarg: CvssArgs)`,
  `display_score`, `ScoreDisplayData`.

**Tests** (`tests/cvss2/`):
- `test_usecases.py` drives the use-case fixtures (`tests/cvss2/test_uc*.txt`)
  via the `cvss2` binary.
- `tests/cvss2/test_uc02_out.txt` is the fixture for interactive output —
  changing `select_metric_value`'s `###| |###` trace requires updating it.
