"""CLI handlers for CVSS v4.0."""

from cvss.cli import exit_with_error as _exit_with_error

from .cvss_40 import CommonVulnerabilityScore40
from .cvss_types import CVSS40Result, CvssArgs
from .vulnerability_40 import InvalidVectorError, VulnerabilityVector40


def _cvs_from_vector(vector: str) -> CVSS40Result:
    try:
        return CommonVulnerabilityScore40(VulnerabilityVector40(vector).parsed)
    except (InvalidVectorError, ValueError) as e:
        _exit_with_error(e)


def process_cmd_line(clarg: CvssArgs) -> CVSS40Result:
    """Dispatch to the appropriate handler."""
    vec = clarg["vulnerability"] or clarg["vector"]
    assert vec is not None
    return _cvs_from_vector(vec)
