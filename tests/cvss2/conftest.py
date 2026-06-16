"""Shared test helpers for cvss2 tests."""

from cvss2.cvss_types import CvssArgs


def make_clarg(**kwargs: object) -> CvssArgs:
    base: CvssArgs = {
        "verbose": False, "interactive": False, "all": False,
        "base": False, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": None,
    }
    return {**base, **kwargs}  # type: ignore[return-value]
