"""Tests for the CvssArgs TypedDict."""

from cvss.cvss_types import CvssArgs


def test_cvss_args_is_typed_dict() -> None:
    d: CvssArgs = {
        "verbose": False,
        "interactive": False,
        "all": False,
        "base": True,
        "temporal": False,
        "environmental": False,
        "vector": "AV:L/AC:M/Au:N/C:N/I:P/A:C",
        "vulnerability": None,
    }
    assert d["base"] is True
    assert d["vector"] is not None


def test_cvss_args_optional_fields_accept_none() -> None:
    d: CvssArgs = {
        "verbose": False,
        "interactive": False,
        "all": False,
        "base": False,
        "temporal": False,
        "environmental": False,
        "vector": None,
        "vulnerability": None,
    }
    assert d["vector"] is None
    assert d["vulnerability"] is None
