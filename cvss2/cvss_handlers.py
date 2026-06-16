"""CVSS v2.10 command handlers and dispatch for all CLI modes."""

from collections.abc import Callable
from typing import cast

from cvss.cli import exit_with_error as _exit_with_error

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_input import read_metrics
from .cvss_types import CvssArgs
from .vulnerability import (
    InvalidVectorError,
    MetricDefinition,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
)

_MetricFn = Callable[[], list[MetricDefinition]]


def _cvs_from_vector(
    vector: str, require_complete: bool = True
) -> CVSS:
    try:
        vvec = VulnerabilityVector(vector)
        mvs = (
            vvec.complete().metric_values()
            if require_complete
            else vvec.valid().metric_values()
        )
        return cvs_factory(CommonVulnerabilityScore, mvs)
    except (InvalidVectorError, ValueError) as e:
        _exit_with_error(e)


def process_cmd_line_base(vector: str) -> CVSS:
    return _cvs_from_vector(vector, require_complete=True)


def process_cmd_line_vulnerability(vulnerability: str) -> CVSS:
    return _cvs_from_vector(vulnerability, require_complete=False)


def _accumulate_groups(
    clarg: CvssArgs,
    base_fn: _MetricFn,
    temporal_fn: _MetricFn,
    env_fn: _MetricFn,
) -> list[str]:
    """Read metrics interactively (no pre-existing vector)."""
    selected: list[str] = []
    if clarg["all"]:
        groups: list[_MetricFn] = [base_fn, temporal_fn, env_fn]
    elif clarg["base"]:
        groups = [
            fn
            for active, fn in [
                (True, base_fn),
                (clarg["temporal"], temporal_fn),
                (clarg["temporal"] and clarg["environmental"], env_fn),
            ]
            if active
        ]
    else:
        return selected
    for fn in groups:
        selected.extend(read_metrics(fn()))
    return selected


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSS:
    if clarg["base"] and clarg["vector"]:
        try:
            vvec = VulnerabilityVector(clarg["vector"])
            selected = list(vvec.complete().metric_values())
        except (InvalidVectorError, ValueError) as e:
            _exit_with_error(e)
        if clarg["temporal"]:
            selected.extend(read_metrics(temporal_metrics()))
            if clarg["environmental"]:
                selected.extend(read_metrics(environmental_metrics()))
    else:
        selected = _accumulate_groups(
            clarg,
            base_fn=base_metrics,
            temporal_fn=temporal_metrics,
            env_fn=environmental_metrics,
        )
    return cvs_factory(CommonVulnerabilityScore, selected)


def process_cmd_line(clarg: CvssArgs) -> CVSS:
    """Dispatch to the appropriate command-line handler."""
    if clarg["interactive"]:
        return process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        return process_cmd_line_base(cast(str, clarg["vector"]))
    elif clarg["vulnerability"]:
        return process_cmd_line_vulnerability(clarg["vulnerability"])
    raise RuntimeError("unreachable")
