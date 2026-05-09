"""Tests for CvssArgs TypedDict and ScoreEntry NamedTuple."""

from cvss.cvss import build_parser
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


def test_parser_keys_match_cvss_args() -> None:
    """Verify build_parser() argument names stay in sync with CvssArgs."""
    parser_keys = set(vars(build_parser().parse_args([])).keys())
    cvss_args_keys = set(CvssArgs.__required_keys__)
    assert parser_keys == cvss_args_keys, (
        f"Key drift: parser has {parser_keys - cvss_args_keys!r} "
        f"extra, CvssArgs has {cvss_args_keys - parser_keys!r} extra"
    )


def test_score_entry_named_access() -> None:
    e = ScoreEntry("Base", 7.5, "AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert e.name == "Base"
    assert e.value == 7.5
    assert e.vector == "AV:N/AC:L/Au:N/C:C/I:C/A:C"
