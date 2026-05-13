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


def render_output(cvs: CVSS40Result) -> None:
    print()
    print(f"CVSS v4.0 Score = {cvs.base_score}")
    print(f"Severity = {qualitative_rating(cvs.base_score)}")
    print(
        f"CVSS v4.0 Vulnerability Vector = {cvs.base_vulnerability_vector}"
    )
    print()
