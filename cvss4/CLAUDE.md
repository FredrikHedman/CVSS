# cvss4/ architecture

CVSS v4.0 calculator, no interactive mode. Shared internals live in `cvss/`
(see root `CLAUDE.md`); global commands and tooling are also documented
there.

**Data layer** (`cvss4/vulnerability_40.py`):
- Imports `MetricDefinition`, `MetricValueDef`, `InvalidVectorError` from
  `cvss.vulnerability`.
- `BASE40_DEFINITIONS`, `THREAT40_DEFINITIONS`,
  `ENVIRONMENTAL40_DEFINITIONS`, `SUPPLEMENTAL40_DEFINITIONS` — four metric
  groups (Spec §7.1-§7.4).
- `VulnerabilityVector40` validates and parses `CVSS:4.0/` vectors on
  construction. `parsed` is a `cached_property` returning `dict[str, str]`
  (absent metrics default to `"X"`).
- `_ALL_ALLOWED` — validation dict derived from all four definition groups.

**Scoring layer** (`cvss4/cvss_40.py`):
- `CommonVulnerabilityScore40` — standalone class (does not inherit from
  the v2.10 `CVSS` ABC). Uses MacroVector lookup table (270 entries) +
  EQ-set interpolation (Spec §7-§8).
- `macro_vector` property — returns `EQLevels` NamedTuple of the six EQ
  level integers.
- `_eq1`-`_eq6` — module-level pure EQ classification functions.
- `_DistSpec` dataclass — per-EQ distance configuration.
- `EQLevels` NamedTuple — named EQ level access.
- `_metrics` — `cached_property` (lazy; not triggered by `base_score`).

**CLI layer** (`cvss4/cvss.py`, `cvss4/cvss_parser.py`,
`cvss4/cvss_handlers.py`, `cvss4/cvss_output.py`, `cvss4/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) — 4 keys: `verbose`, `base`, `vector`,
  `vulnerability`. No interactive/temporal/environmental/all.
- `CVSS40Result` protocol — `@runtime_checkable`; satisfied by
  `CommonVulnerabilityScore40`.
- `cvss4` has **no interactive mode**. Only `--base <vector>` and
  `--vulnerability <vector>`.
- `cvss_output.py`: `format_output(cvs: CVSS40Result, clarg: CvssArgs) -> str`.

**Tests** (`tests/cvss4/`):
- `test_cvss_40.py` — unit and scoring tests (15 spec examples, EQ
  boundary conditions, protocol checks).
- `test_cli.py` — integration tests via `cvss4` binary.
- `test_display.py` — output function tests.
