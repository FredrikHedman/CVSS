# cvss4/ architecture

CVSS v4.0 calculator, no interactive mode. Shared utilities live in
`cvss/__init__.py` (see root `CLAUDE.md`); global commands and tooling
are also documented there.

**Data layer** (`cvss4/vulnerability_40.py`):
- Imports `InvalidVectorError` from `cvss`.
- Defines `_V40Value` (name, abbrev, description) and `_V40Def` (name,
  abbrev, values) — cvss4-specific types with **no weight field** (scoring
  uses a lookup table, not weighted formulas).
- `BASE40_DEFINITIONS`, `THREAT40_DEFINITIONS`,
  `ENVIRONMENTAL40_DEFINITIONS`, `SUPPLEMENTAL40_DEFINITIONS` — four metric
  groups (Spec §7.1-§7.4), typed as `tuple[_V40Def, ...]`.
- `VulnerabilityVector40` validates and parses `CVSS:4.0/` vectors on
  construction. `parsed` is a `cached_property` returning `dict[str, str]`
  (absent metrics default to `"X"`).
- `_ALL_ALLOWED` — validation dict derived from all four definition groups.

**Scoring layer** (`cvss4/cvss_40.py`):
- `CommonVulnerabilityScore40` — standalone class (does not inherit from
  the v2.10 `CVSS` ABC). Uses MacroVector lookup table (270 entries) +
  EQ-set interpolation (Spec §7-§8).
- `macro_vector` property — returns `EQLevels` NamedTuple (six integers,
  one per equivalence set EQ1–EQ6; defined in `cvss_40.py`).
- `_eq1`-`_eq6` — module-level pure EQ classification functions.
- `_DistSpec` dataclass — per-EQ distance configuration.
- `_display_for(defs)` — builds `list[MetricDisplay]` for verbose output;
  not triggered by `base_score`.

**CLI layer** (`cvss4/cvss.py`, `cvss4/cvss_parser.py`,
`cvss4/cvss_handlers.py`, `cvss4/cvss_output.py`, `cvss4/cvss_types.py`):
- `CvssArgs` (`cvss_types.py`) — 4 keys: `verbose`, `base`, `vector`,
  `vulnerability`. No interactive/temporal/environmental/all.
- `MetricDisplay` (`cvss_types.py`) — frozen dataclass (name, value, abbrev)
  for one row in the verbose metric table.
- `CVSS40Result` protocol — `@runtime_checkable`; satisfied by
  `CommonVulnerabilityScore40`.
- `cvss4` has **no interactive mode**. Only `--base <vector>` and
  `--vulnerability <vector>`.
- `cvss_output.py`: `format_output(cvs: CVSS40Result, clarg: CvssArgs) -> str`;
  local `_print_metric_group` and `_print_separator` (no longer imported
  from `cvss.output`).

**Tests** (`tests/cvss4/`):
- `test_cvss_40.py` — unit and scoring tests (15 spec examples, EQ
  boundary conditions, protocol checks).
- `test_cli.py` — integration tests via `cvss4` binary.
- `test_display.py` — output function tests.
