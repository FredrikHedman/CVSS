"""Output rendering for CVSS v4.0."""

from .cvss_types import CVSS40Result


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


def render_output(cvs: CVSS40Result) -> None:
    label = _score_label(cvs)
    print()
    print(f"{label} Score = {cvs.base_score}")
    print(f"Severity = {qualitative_rating(cvs.base_score)}")
    print(
        f"CVSS v4.0 Vulnerability Vector = {cvs.base_vulnerability_vector}"
    )
    print()
