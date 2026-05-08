"""Tests for CvssArgs TypedDict and ScoreEntry NamedTuple."""

from cvss.cvss_types import CvssArgs, ScoreEntry


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


def test_score_entry_named_access() -> None:
    e = ScoreEntry("Base", 7.5, "AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert e.name == "Base"
    assert e.value == 7.5
    assert e.vector == "AV:N/AC:L/Au:N/C:C/I:C/A:C"
