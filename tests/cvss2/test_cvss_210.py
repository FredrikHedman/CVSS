"""Tests for CommonVulnerabilityScore."""

import pytest

from cvss2.cvss_210 import CommonVulnerabilityScore
from cvss.metric import Metric


def test_duplicate_short_name_raises() -> None:
    m1 = Metric("Access Vector", "AV", [("Local", "L", 0.395, "Local access")])
    m2 = Metric(
        "Access Vector Dup", "AV", [("Local", "L", 0.395, "Local access")]
    )
    with pytest.raises(ValueError, match="collision"):
        _ = CommonVulnerabilityScore([m1, m2])
