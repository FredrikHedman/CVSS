"""Output rendering for CVSS v4.0."""

import contextlib
import io

from .cvss_types import CVSS40Result, CvssArgs
from cvss.metric import Metric


def qualitative_rating(score: float) -> str:
    """Map a v4.0 score to a severity label (Spec §9)."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _score_label(cvs: CVSS40Result) -> str:
    """Return CVSS-B/BT/BE/BTE nomenclature label (Implementation Guide §4).

    The label reflects which metric groups were explicitly provided:
    B = base only, BT = + threat, BE = + environmental, BTE = all three.
    """
    has_threat = any(m.index != "X" for m in cvs.threat_metrics())
    has_env = any(m.index != "X" for m in cvs.environmental_metrics())
    if has_threat and has_env:
        return "CVSS-BTE"
    if has_threat:
        return "CVSS-BT"
    if has_env:
        return "CVSS-BE"
    return "CVSS-B"


_W = 44
_SEP = "=" * (_W * 2 + 6)


def _print_group(header: str, metrics: list[Metric]) -> None:
    print(_SEP)
    print(f"{header:<{_W}}{'EVALUATION':<{_W}}{'ABBREV'}")
    print(_SEP)
    for m in metrics:
        print(f"{m.name:<{_W}}{m.selected.metric:<{_W}}{m.index}")


def _render_verbose(cvs: CVSS40Result) -> None:
    label = _score_label(cvs)
    mv = cvs.macro_vector
    for group_name, group_metrics in [
        ("BASE METRICS", cvs.base_metrics()),
        ("THREAT METRICS", cvs.threat_metrics()),
        ("ENVIRONMENTAL METRICS", cvs.environmental_metrics()),
        ("SUPPLEMENTAL METRICS", cvs.supplemental_metrics()),
    ]:
        _print_group(group_name, group_metrics)
    print(_SEP)
    print()
    eq = f"[{mv[0]}, {mv[1]}, {mv[2]}, {mv[3]}, {mv[4]}, {mv[5]}]"
    print(f"MacroVector EQ: {eq}")
    print(f"{label} Score = {cvs.base_score}")
    print(f"Severity = {qualitative_rating(cvs.base_score)}")
    print(
        f"CVSS v4.0 Vulnerability Vector = {cvs.base_vulnerability_vector}"
    )
    print()


def format_output(cvs: CVSS40Result, clarg: CvssArgs) -> str:
    """Return scores formatted as a string (verbose or standard)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        if clarg["verbose"]:
            _render_verbose(cvs)
        else:
            label = _score_label(cvs)
            print()
            print(f"{label} Score = {cvs.base_score}")
            print(f"Severity = {qualitative_rating(cvs.base_score)}")
            vec = cvs.base_vulnerability_vector
            print(f"CVSS v4.0 Vulnerability Vector = {vec}")
            print()
    return buf.getvalue()
