"""CVSS v4.0 scoring implementation.

Algorithm: CVSS v4.0 Specification §7 (Equivalence Sets), §8 (MacroVector
lookup + interpolation). Lookup table and MAX_COMPOSED/MAX_SEVERITY constants
sourced from the RedHatProductSecurity/cvss reference implementation, which
mirrors the FIRST calculator (Spec §8.3, cvss_lookup.js).

This class does NOT inherit from the v2.10 CVSS ABC because v4.0 scoring uses
a lookup-table approach rather than closed-form formulas. See README
§Architecture for rationale.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Callable, NamedTuple

from .metric import Metric
from .vulnerability_40 import (
    BASE40_DEFINITIONS,
    ENVIRONMENTAL40_DEFINITIONS,
    SUPPLEMENTAL40_DEFINITIONS,
    THREAT40_DEFINITIONS,
)

# ---------------------------------------------------------------------------
# Metric level dictionaries — float severity (0.0 = most severe, 0.1 steps)
# Source: RedHatProductSecurity/cvss cvss4.py compute_base_score()
# ---------------------------------------------------------------------------
_AV = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC = {"L": 0.0, "H": 0.1}
_AT = {"N": 0.0, "P": 0.1}
_VC = {"H": 0.0, "L": 0.1, "N": 0.2}
_VI = {"H": 0.0, "L": 0.1, "N": 0.2}
_VA = {"H": 0.0, "L": 0.1, "N": 0.2}
_SC = {"H": 0.1, "L": 0.2, "N": 0.3}   # starts at 0.1, not 0.0
_SI = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_SA = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CR = {"H": 0.0, "M": 0.1, "L": 0.2}
_IR = {"H": 0.0, "M": 0.1, "L": 0.2}
_AR = {"H": 0.0, "M": 0.1, "L": 0.2}
_E  = {"A": 0.0, "P": 0.1, "U": 0.2}   # X is mapped to A before lookup

# ---------------------------------------------------------------------------
# _DistSpec: declarative per-metric distance specification
# ---------------------------------------------------------------------------


@dataclass
class _DistSpec:
    key: str
    ldict: dict[str, float]
    mv_default: str        # most-severe value used in MAX_COMPOSED candidates
    mod: str | None = None   # modifier key: use _eff(mod, key) not _v(key)
    x_sub: str | None = None  # if effective value == "X", substitute this


_EQ1_SPECS: list[_DistSpec] = [
    _DistSpec("AV", _AV, "N"),
    _DistSpec("PR", _PR, "N"),
    _DistSpec("UI", _UI, "N"),
]
_EQ2_SPECS: list[_DistSpec] = [
    _DistSpec("AC", _AC, "L"),
    _DistSpec("AT", _AT, "N"),
]
_EQ3EQ6_SPECS: list[_DistSpec] = [
    _DistSpec("VC", _VC, "H", mod="MVC"),
    _DistSpec("VI", _VI, "H", mod="MVI"),
    _DistSpec("VA", _VA, "H", mod="MVA"),
    _DistSpec("CR", _CR, "H", x_sub="H"),   # X → H (high requirement)
    _DistSpec("IR", _IR, "H", x_sub="H"),
    _DistSpec("AR", _AR, "H", x_sub="H"),
]
_EQ4_SPECS: list[_DistSpec] = [
    _DistSpec("SC", _SC, "H", mod="MSC"),
    _DistSpec("SI", _SI, "H", mod="MSI"),
    _DistSpec("SA", _SA, "H", mod="MSA"),
]
_EQ5_SPECS: list[_DistSpec] = [
    _DistSpec("E", _E, "A", x_sub="A"),     # X → A (Attacked, Spec §7.4)
]

# ---------------------------------------------------------------------------
# MAX_COMPOSED: canonical highest-severity vectors per EQ level
# Source: RedHatProductSecurity/cvss constants4.py MAX_COMPOSED
# ---------------------------------------------------------------------------
_EQ1_MAX: dict[str, list[str]] = {
    "0": ["AV:N/PR:N/UI:N/"],
    "1": ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    "2": ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
}
_EQ2_MAX: dict[str, list[str]] = {
    "0": ["AC:L/AT:N/"],
    "1": ["AC:H/AT:N/", "AC:L/AT:P/"],
}
# EQ3 and EQ6 are combined; keyed by (str(eq3), str(eq6))
_EQ3EQ6_MAX: dict[str, dict[str, list[str]]] = {
    "0": {
        "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        "1": [
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ],
    },
    "1": {
        "0": [
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ],
        "1": [
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
    },
    "2": {
        "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    },
}
_EQ4_MAX: dict[str, list[str]] = {
    "0": ["SC:H/SI:S/SA:S/"],
    "1": ["SC:H/SI:H/SA:H/"],
    "2": ["SC:L/SI:L/SA:L/"],
}
_EQ5_MAX: dict[str, list[str]] = {
    "0": ["E:A/"],
    "1": ["E:P/"],
    "2": ["E:U/"],
}

# ---------------------------------------------------------------------------
# MAX_SEVERITY: maximum severity distance per EQ level (× 0.1 = float units)
# Source: RedHatProductSecurity/cvss constants4.py MAX_SEVERITY
# ---------------------------------------------------------------------------
_SEV_EQ1 = {0: 1, 1: 4, 2: 5}
_SEV_EQ2 = {0: 1, 1: 2}
_SEV_EQ3EQ6: dict[tuple[int, int], int] = {
    (0, 0): 7, (0, 1): 6,
    (1, 0): 8, (1, 1): 8,
    (2, 1): 10,
}
_SEV_EQ4 = {0: 6, 1: 5, 2: 4}
_SEV_EQ5 = {0: 1, 1: 1, 2: 1}

# ---------------------------------------------------------------------------
# MacroVector lookup table (Spec §8.3, 270 valid entries)
# ---------------------------------------------------------------------------
_LOOKUP: dict[tuple[int, int, int, int, int, int], float] = {
    # eq1=0, eq2=0, eq3=0
    (0,0,0,0,0,0):10.0, (0,0,0,0,0,1):9.9,
    (0,0,0,0,1,0):9.8,  (0,0,0,0,1,1):9.5,
    (0,0,0,0,2,0):9.5,  (0,0,0,0,2,1):9.2,
    (0,0,0,1,0,0):10.0, (0,0,0,1,0,1):9.6,
    (0,0,0,1,1,0):9.3,  (0,0,0,1,1,1):8.7,
    (0,0,0,1,2,0):9.1,  (0,0,0,1,2,1):8.1,
    (0,0,0,2,0,0):9.3,  (0,0,0,2,0,1):9.0,
    (0,0,0,2,1,0):8.9,  (0,0,0,2,1,1):8.0,
    (0,0,0,2,2,0):8.1,  (0,0,0,2,2,1):6.8,
    # eq1=0, eq2=0, eq3=1
    (0,0,1,0,0,0):9.8,  (0,0,1,0,0,1):9.5,
    (0,0,1,0,1,0):9.5,  (0,0,1,0,1,1):9.2,
    (0,0,1,0,2,0):9.0,  (0,0,1,0,2,1):8.4,
    (0,0,1,1,0,0):9.3,  (0,0,1,1,0,1):9.2,
    (0,0,1,1,1,0):8.9,  (0,0,1,1,1,1):8.1,
    (0,0,1,1,2,0):8.1,  (0,0,1,1,2,1):6.5,
    (0,0,1,2,0,0):8.8,  (0,0,1,2,0,1):8.0,
    (0,0,1,2,1,0):7.8,  (0,0,1,2,1,1):7.0,
    (0,0,1,2,2,0):6.9,  (0,0,1,2,2,1):4.8,
    # eq1=0, eq2=0, eq3=2 (EQ6 always 1)
    (0,0,2,0,0,1):9.2, (0,0,2,0,1,1):8.2, (0,0,2,0,2,1):7.2,
    (0,0,2,1,0,1):7.9, (0,0,2,1,1,1):6.9, (0,0,2,1,2,1):5.0,
    (0,0,2,2,0,1):6.9, (0,0,2,2,1,1):5.5, (0,0,2,2,2,1):2.7,
    # eq1=0, eq2=1, eq3=0
    (0,1,0,0,0,0):9.9, (0,1,0,0,0,1):9.7,
    (0,1,0,0,1,0):9.2, (0,1,0,0,1,1):9.2,
    (0,1,0,0,2,0):9.2, (0,1,0,0,2,1):8.5,
    (0,1,0,1,0,0):9.5, (0,1,0,1,0,1):9.1,
    (0,1,0,1,1,0):9.0, (0,1,0,1,1,1):8.3,
    (0,1,0,1,2,0):8.4, (0,1,0,1,2,1):7.1,
    (0,1,0,2,0,0):9.2, (0,1,0,2,0,1):8.1,
    (0,1,0,2,1,0):8.2, (0,1,0,2,1,1):7.1,
    (0,1,0,2,2,0):7.2, (0,1,0,2,2,1):5.3,
    # eq1=0, eq2=1, eq3=1
    (0,1,1,0,0,0):9.5, (0,1,1,0,0,1):9.3,
    (0,1,1,0,1,0):9.2, (0,1,1,0,1,1):8.5,
    (0,1,1,0,2,0):8.5, (0,1,1,0,2,1):7.3,
    (0,1,1,1,0,0):9.2, (0,1,1,1,0,1):8.2,
    (0,1,1,1,1,0):8.0, (0,1,1,1,1,1):7.2,
    (0,1,1,1,2,0):7.0, (0,1,1,1,2,1):5.9,
    (0,1,1,2,0,0):8.4, (0,1,1,2,0,1):7.0,
    (0,1,1,2,1,0):7.1, (0,1,1,2,1,1):5.2,
    (0,1,1,2,2,0):5.0, (0,1,1,2,2,1):3.0,
    # eq1=0, eq2=1, eq3=2 (EQ6 always 1)
    (0,1,2,0,0,1):8.6, (0,1,2,0,1,1):7.5, (0,1,2,0,2,1):5.2,
    (0,1,2,1,0,1):7.1, (0,1,2,1,1,1):5.2, (0,1,2,1,2,1):2.9,
    (0,1,2,2,0,1):6.3, (0,1,2,2,1,1):2.9, (0,1,2,2,2,1):1.7,
    # eq1=1, eq2=0, eq3=0
    (1,0,0,0,0,0):9.8, (1,0,0,0,0,1):9.5,
    (1,0,0,0,1,0):9.4, (1,0,0,0,1,1):8.7,
    (1,0,0,0,2,0):9.1, (1,0,0,0,2,1):8.1,
    (1,0,0,1,0,0):9.4, (1,0,0,1,0,1):8.9,
    (1,0,0,1,1,0):8.6, (1,0,0,1,1,1):7.4,
    (1,0,0,1,2,0):7.7, (1,0,0,1,2,1):6.4,
    (1,0,0,2,0,0):8.7, (1,0,0,2,0,1):7.5,
    (1,0,0,2,1,0):7.4, (1,0,0,2,1,1):6.3,
    (1,0,0,2,2,0):6.3, (1,0,0,2,2,1):4.9,
    # eq1=1, eq2=0, eq3=1
    (1,0,1,0,0,0):9.4, (1,0,1,0,0,1):8.9,
    (1,0,1,0,1,0):8.8, (1,0,1,0,1,1):7.7,
    (1,0,1,0,2,0):7.6, (1,0,1,0,2,1):6.7,
    (1,0,1,1,0,0):8.6, (1,0,1,1,0,1):7.6,
    (1,0,1,1,1,0):7.4, (1,0,1,1,1,1):5.8,
    (1,0,1,1,2,0):5.9, (1,0,1,1,2,1):5.0,
    (1,0,1,2,0,0):7.2, (1,0,1,2,0,1):5.7,
    (1,0,1,2,1,0):5.7, (1,0,1,2,1,1):5.2,
    (1,0,1,2,2,0):5.2, (1,0,1,2,2,1):2.5,
    # eq1=1, eq2=0, eq3=2 (EQ6 always 1)
    (1,0,2,0,0,1):8.3, (1,0,2,0,1,1):7.0, (1,0,2,0,2,1):5.4,
    (1,0,2,1,0,1):6.5, (1,0,2,1,1,1):5.8, (1,0,2,1,2,1):2.6,
    (1,0,2,2,0,1):5.3, (1,0,2,2,1,1):2.1, (1,0,2,2,2,1):1.3,
    # eq1=1, eq2=1, eq3=0
    (1,1,0,0,0,0):9.5, (1,1,0,0,0,1):9.0,
    (1,1,0,0,1,0):8.8, (1,1,0,0,1,1):7.6,
    (1,1,0,0,2,0):7.6, (1,1,0,0,2,1):7.0,
    (1,1,0,1,0,0):9.0, (1,1,0,1,0,1):7.7,
    (1,1,0,1,1,0):7.5, (1,1,0,1,1,1):6.2,
    (1,1,0,1,2,0):6.1, (1,1,0,1,2,1):5.3,
    (1,1,0,2,0,0):7.7, (1,1,0,2,0,1):6.6,
    (1,1,0,2,1,0):6.8, (1,1,0,2,1,1):5.9,
    (1,1,0,2,2,0):5.2, (1,1,0,2,2,1):3.0,
    # eq1=1, eq2=1, eq3=1
    (1,1,1,0,0,0):8.9, (1,1,1,0,0,1):7.8,
    (1,1,1,0,1,0):7.6, (1,1,1,0,1,1):6.7,
    (1,1,1,0,2,0):6.2, (1,1,1,0,2,1):5.8,
    (1,1,1,1,0,0):7.4, (1,1,1,1,0,1):5.9,
    (1,1,1,1,1,0):5.7, (1,1,1,1,1,1):5.7,
    (1,1,1,1,2,0):4.7, (1,1,1,1,2,1):2.3,
    (1,1,1,2,0,0):6.1, (1,1,1,2,0,1):5.2,
    (1,1,1,2,1,0):5.7, (1,1,1,2,1,1):2.9,
    (1,1,1,2,2,0):2.4, (1,1,1,2,2,1):1.6,
    # eq1=1, eq2=1, eq3=2 (EQ6 always 1)
    (1,1,2,0,0,1):7.1, (1,1,2,0,1,1):5.9, (1,1,2,0,2,1):3.0,
    (1,1,2,1,0,1):5.8, (1,1,2,1,1,1):2.6, (1,1,2,1,2,1):1.5,
    (1,1,2,2,0,1):2.3, (1,1,2,2,1,1):1.3, (1,1,2,2,2,1):0.6,
    # eq1=2, eq2=0, eq3=0
    (2,0,0,0,0,0):9.3, (2,0,0,0,0,1):8.7,
    (2,0,0,0,1,0):8.6, (2,0,0,0,1,1):7.2,
    (2,0,0,0,2,0):7.5, (2,0,0,0,2,1):5.8,
    (2,0,0,1,0,0):8.6, (2,0,0,1,0,1):7.4,
    (2,0,0,1,1,0):7.4, (2,0,0,1,1,1):6.1,
    (2,0,0,1,2,0):5.6, (2,0,0,1,2,1):3.4,
    (2,0,0,2,0,0):7.0, (2,0,0,2,0,1):5.4,
    (2,0,0,2,1,0):5.2, (2,0,0,2,1,1):4.0,
    (2,0,0,2,2,0):4.0, (2,0,0,2,2,1):2.2,
    # eq1=2, eq2=0, eq3=1
    (2,0,1,0,0,0):8.5, (2,0,1,0,0,1):7.5,
    (2,0,1,0,1,0):7.4, (2,0,1,0,1,1):5.5,
    (2,0,1,0,2,0):6.2, (2,0,1,0,2,1):5.1,
    (2,0,1,1,0,0):7.2, (2,0,1,1,0,1):5.7,
    (2,0,1,1,1,0):5.5, (2,0,1,1,1,1):4.1,
    (2,0,1,1,2,0):4.6, (2,0,1,1,2,1):1.9,
    (2,0,1,2,0,0):5.3, (2,0,1,2,0,1):3.6,
    (2,0,1,2,1,0):3.4, (2,0,1,2,1,1):1.9,
    (2,0,1,2,2,0):1.9, (2,0,1,2,2,1):0.8,
    # eq1=2, eq2=0, eq3=2 (EQ6 always 1)
    (2,0,2,0,0,1):6.4, (2,0,2,0,1,1):5.1, (2,0,2,0,2,1):2.0,
    (2,0,2,1,0,1):4.7, (2,0,2,1,1,1):2.1, (2,0,2,1,2,1):1.1,
    (2,0,2,2,0,1):2.4, (2,0,2,2,1,1):0.9, (2,0,2,2,2,1):0.4,
    # eq1=2, eq2=1, eq3=0
    (2,1,0,0,0,0):8.8, (2,1,0,0,0,1):7.5,
    (2,1,0,0,1,0):7.3, (2,1,0,0,1,1):5.3,
    (2,1,0,0,2,0):6.0, (2,1,0,0,2,1):5.0,
    (2,1,0,1,0,0):7.3, (2,1,0,1,0,1):5.5,
    (2,1,0,1,1,0):5.9, (2,1,0,1,1,1):4.0,
    (2,1,0,1,2,0):4.1, (2,1,0,1,2,1):2.0,
    (2,1,0,2,0,0):5.4, (2,1,0,2,0,1):4.3,
    (2,1,0,2,1,0):4.5, (2,1,0,2,1,1):2.2,
    (2,1,0,2,2,0):2.0, (2,1,0,2,2,1):1.1,
    # eq1=2, eq2=1, eq3=1
    (2,1,1,0,0,0):7.5, (2,1,1,0,0,1):5.5,
    (2,1,1,0,1,0):5.8, (2,1,1,0,1,1):4.5,
    (2,1,1,0,2,0):4.0, (2,1,1,0,2,1):2.1,
    (2,1,1,1,0,0):6.1, (2,1,1,1,0,1):5.1,
    (2,1,1,1,1,0):4.8, (2,1,1,1,1,1):1.8,
    (2,1,1,1,2,0):2.0, (2,1,1,1,2,1):0.9,
    (2,1,1,2,0,0):4.6, (2,1,1,2,0,1):1.8,
    (2,1,1,2,1,0):1.7, (2,1,1,2,1,1):0.7,
    (2,1,1,2,2,0):0.8, (2,1,1,2,2,1):0.2,
    # eq1=2, eq2=1, eq3=2 (EQ6 always 1)
    (2,1,2,0,0,1):5.3, (2,1,2,0,1,1):2.4, (2,1,2,0,2,1):1.4,
    (2,1,2,1,0,1):2.4, (2,1,2,1,1,1):1.2, (2,1,2,1,2,1):0.5,
    (2,1,2,2,0,1):1.0, (2,1,2,2,1,1):0.3, (2,1,2,2,2,1):0.1,
}


def _parse_vec(vec_str: str) -> dict[str, str]:
    """Parse 'AV:N/PR:N/UI:N/' into {'AV': 'N', 'PR': 'N', 'UI': 'N'}."""
    result: dict[str, str] = {}
    for part in vec_str.rstrip("/").split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            result[k] = v
    return result


class _EQLevels(NamedTuple):
    """Six Equivalence Set levels, one per EQ dimension (Spec §7.5)."""
    eq1: int
    eq2: int
    eq3: int
    eq4: int
    eq5: int
    eq6: int


class CommonVulnerabilityScore40:
    """CVSS v4.0 scorer: MacroVector lookup + interpolation (Spec §7–§8)."""

    def __init__(self, parsed: dict[str, str]) -> None:
        self._p: dict[str, str] = parsed
        self._metrics: dict[str, Metric] = {}
        all_defs = (
            list(BASE40_DEFINITIONS)
            + list(THREAT40_DEFINITIONS)
            + list(ENVIRONMENTAL40_DEFINITIONS)
            + list(SUPPLEMENTAL40_DEFINITIONS)
        )
        for d in all_defs:
            val = parsed.get(d.abbrev, "X")
            try:
                m = Metric(d.name, d.abbrev, d.metric_values(), index=val)
            except ValueError:
                m = Metric(d.name, d.abbrev, d.metric_values())
            self._metrics[d.abbrev] = m

    def _v(self, key: str) -> str:
        return self._p.get(key, "X")

    def _eff(self, mod: str, base: str) -> str:
        m = self._v(mod)
        return self._v(base) if m == "X" else m

    # ------------------------------------------------------------------
    # EQ level computation (Spec §7.5)
    # ------------------------------------------------------------------

    def _eq1(self) -> int:
        av, pr, ui = self._v("AV"), self._v("PR"), self._v("UI")
        if av == "N" and pr == "N" and ui == "N":
            return 0
        if av == "N" or pr == "N" or ui == "N":
            return 1
        return 2

    def _eq2(self) -> int:
        return 0 if self._v("AC") == "L" and self._v("AT") == "N" else 1

    def _eq3(self) -> int:
        vc, vi, va = self._v("VC"), self._v("VI"), self._v("VA")
        if vc == "H" and vi == "H":
            return 0
        if vc == "H" or vi == "H" or va == "H":
            return 1
        return 2

    def _eq4(self) -> int:
        eff_si = self._eff("MSI", "SI")
        eff_sa = self._eff("MSA", "SA")
        if eff_si == "S" or eff_sa == "S":
            return 0
        eff_sc = self._eff("MSC", "SC")
        if eff_sc == "H" or eff_si == "H" or eff_sa == "H":
            return 1
        return 2

    def _eq5(self) -> int:
        e = self._v("E")
        eff = "A" if e == "X" else e
        if eff == "A":
            return 0
        if eff == "P":
            return 1
        return 2

    def _eq6(self) -> int:
        eff_vc = self._eff("MVC", "VC")
        eff_vi = self._eff("MVI", "VI")
        eff_va = self._eff("MVA", "VA")
        cr, ir, ar = self._v("CR"), self._v("IR"), self._v("AR")
        eff_cr = "H" if cr == "X" else cr
        eff_ir = "H" if ir == "X" else ir
        eff_ar = "H" if ar == "X" else ar
        if ((eff_cr == "H" and eff_vc == "H")
                or (eff_ir == "H" and eff_vi == "H")
                or (eff_ar == "H" and eff_va == "H")):
            return 0
        return 1

    def _eq_levels(self) -> _EQLevels:
        return _EQLevels(
            self._eq1(), self._eq2(), self._eq3(),
            self._eq4(), self._eq5(), self._eq6(),
        )

    # ------------------------------------------------------------------
    # Per-EQ severity distance helpers
    # ------------------------------------------------------------------

    def _metric_eff(self, spec: _DistSpec) -> str:
        v = self._eff(spec.mod, spec.key) if spec.mod else self._v(spec.key)
        return spec.x_sub if spec.x_sub and v == "X" else v

    def _dist_from_specs(
        self, mv: dict[str, str], specs: list[_DistSpec]
    ) -> float | None:
        diffs = [
            spec.ldict.get(self._metric_eff(spec), 0.0)
            - spec.ldict.get(mv.get(spec.key, spec.mv_default), 0.0)
            for spec in specs
        ]
        if any(d < 0 for d in diffs):
            return None
        return sum(diffs)

    def _dist_eq1(self, mv: dict[str, str]) -> float | None:
        return self._dist_from_specs(mv, _EQ1_SPECS)

    def _dist_eq2(self, mv: dict[str, str]) -> float | None:
        return self._dist_from_specs(mv, _EQ2_SPECS)

    def _dist_eq3eq6(self, mv: dict[str, str]) -> float | None:
        return self._dist_from_specs(mv, _EQ3EQ6_SPECS)

    def _dist_eq4(self, mv: dict[str, str]) -> float | None:
        return self._dist_from_specs(mv, _EQ4_SPECS)

    def _dist_eq5(self, mv: dict[str, str]) -> float | None:
        return self._dist_from_specs(mv, _EQ5_SPECS)

    def _find_dist(
        self,
        candidates: list[str],
        fn: Callable[[dict[str, str]], float | None],
    ) -> float:
        for s in candidates:
            d = fn(_parse_vec(s))
            if d is not None:
                return d
        return 0.0

    def _eq_contrib(
        self,
        next_score: float | None,
        mv: float,
        max_vecs: list[str],
        dist_fn: Callable[[dict[str, str]], float | None],
        max_sev: int,
    ) -> tuple[float, int]:
        if next_score is None:
            return 0.0, 0
        avail = mv - next_score
        d = self._find_dist(max_vecs, dist_fn)
        ms = max_sev * 0.1
        return (d / ms if ms else 0.0) * avail, 1

    def _eq3eq6_contrib(
        self,
        levels: _EQLevels,
        mv: float,
    ) -> tuple[float, int]:
        """EQ3+EQ6 combined contribution (Spec §8.3)."""
        eq1, eq2, eq3, eq4, eq5, eq6 = levels
        opts: list[float] = []
        if eq3 < 2:
            nq6 = 1 if eq3 + 1 == 2 else eq6
            s = _LOOKUP.get((eq1, eq2, eq3 + 1, eq4, eq5, nq6))
            if s is not None:
                opts.append(s)
        if eq6 < 1 and eq3 != 2:
            s = _LOOKUP.get((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
            if s is not None:
                opts.append(s)
        if not opts:
            return 0.0, 0
        avail = mv - max(opts)
        cands = _EQ3EQ6_MAX[str(eq3)][str(eq6)]
        d = self._find_dist(cands, self._dist_eq3eq6)
        ms = _SEV_EQ3EQ6.get((eq3, eq6), 0) * 0.1
        return (d / ms if ms else 0.0) * avail, 1

    # ------------------------------------------------------------------
    # Score computation (Spec §8)
    # ------------------------------------------------------------------

    @property
    def version(self) -> str:
        return "4.0"

    @property
    def base_score(self) -> float:
        """CVSS-BTE score (all available metrics, Spec §8)."""
        levels = self._eq_levels()
        mv = _LOOKUP.get(levels)
        if mv is None:
            raise ValueError(f"No lookup entry for EQ levels {levels}")
        eq1, eq2, eq3, eq4, eq5, eq6 = levels

        contribs: list[tuple[float, int]] = [
            self._eq_contrib(
                _LOOKUP.get((eq1 + 1, eq2, eq3, eq4, eq5, eq6))
                if eq1 < 2 else None,
                mv, _EQ1_MAX[str(eq1)], self._dist_eq1, _SEV_EQ1[eq1],
            ),
            self._eq_contrib(
                _LOOKUP.get((eq1, eq2 + 1, eq3, eq4, eq5, eq6))
                if eq2 < 1 else None,
                mv, _EQ2_MAX[str(eq2)], self._dist_eq2, _SEV_EQ2[eq2],
            ),
            self._eq3eq6_contrib(levels, mv),
            self._eq_contrib(
                _LOOKUP.get((eq1, eq2, eq3, eq4 + 1, eq5, eq6))
                if eq4 < 2 else None,
                mv, _EQ4_MAX[str(eq4)], self._dist_eq4, _SEV_EQ4[eq4],
            ),
            self._eq_contrib(
                _LOOKUP.get((eq1, eq2, eq3, eq4, eq5 + 1, eq6))
                if eq5 < 2 else None,
                mv, _EQ5_MAX[str(eq5)], self._dist_eq5, _SEV_EQ5[eq5],
            ),
        ]
        total = sum(c for c, _ in contribs)
        n_lower = sum(n for _, n in contribs)
        value = mv if n_lower == 0 else mv - total / n_lower
        value = max(0.0, min(10.0, value))
        return float(
            Decimal(str(value)).quantize(
                Decimal("0.1"), rounding=ROUND_HALF_UP
            )
        )

    @property
    def base_vulnerability_vector(self) -> str:
        base = "/".join(
            f"{d.abbrev}:{self._p.get(d.abbrev, 'X')}"
            for d in BASE40_DEFINITIONS
        )
        optional = "/".join(
            f"{d.abbrev}:{v}"
            for d in (
                list(THREAT40_DEFINITIONS)
                + list(ENVIRONMENTAL40_DEFINITIONS)
                + list(SUPPLEMENTAL40_DEFINITIONS)
            )
            if (v := self._p.get(d.abbrev)) is not None and v != "X"
        )
        return "CVSS:4.0/" + base + ("/" + optional if optional else "")

    def base_metrics(self) -> list[Metric]:
        return [self._metrics[d.abbrev] for d in BASE40_DEFINITIONS]

    def threat_metrics(self) -> list[Metric]:
        return [self._metrics[d.abbrev] for d in THREAT40_DEFINITIONS]

    def environmental_metrics(self) -> list[Metric]:
        return [self._metrics[d.abbrev] for d in ENVIRONMENTAL40_DEFINITIONS]

    def supplemental_metrics(self) -> list[Metric]:
        return [self._metrics[d.abbrev] for d in SUPPLEMENTAL40_DEFINITIONS]
