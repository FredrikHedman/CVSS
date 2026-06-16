"""Unit tests for cvss4 handlers and parser."""

import pytest

from cvss4.cvss_handlers import (
    _cvs_from_vector,  # pyright: ignore[reportPrivateUsage]
    process_cmd_line,
)
from cvss4.cvss_parser import (
    _validate_flags,  # pyright: ignore[reportPrivateUsage]
    build_parser,
    make_clarg,
)
from cvss4.cvss_types import CvssArgs

_BASE_VECTOR = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)


def _make_clarg(**kwargs: object) -> CvssArgs:
    base: CvssArgs = {
        "verbose": False, "base": False,
        "vector": None, "vulnerability": None,
    }
    return {**base, **kwargs}  # type: ignore[return-value]


# ------------------------------------------------------------------
# _cvs_from_vector
# ------------------------------------------------------------------

def test_cvs_from_vector_valid() -> None:
    cvs = _cvs_from_vector(_BASE_VECTOR)
    assert cvs.base_score == 9.3


def test_cvs_from_vector_invalid_exits() -> None:
    with pytest.raises(SystemExit):
        _ = _cvs_from_vector("BAD:VECTOR")


# ------------------------------------------------------------------
# process_cmd_line
# ------------------------------------------------------------------

def test_process_cmd_line_vulnerability() -> None:
    cvs = process_cmd_line(_make_clarg(vulnerability=_BASE_VECTOR))
    assert cvs.base_score == 9.3


def test_process_cmd_line_base_vector() -> None:
    cvs = process_cmd_line(_make_clarg(base=True, vector=_BASE_VECTOR))
    assert cvs.base_score == 9.3


def test_process_cmd_line_no_vector_exits() -> None:
    with pytest.raises(SystemExit):
        _ = process_cmd_line(_make_clarg())


# ------------------------------------------------------------------
# Parser: make_clarg and _validate_flags
# ------------------------------------------------------------------

def test_make_clarg_defaults() -> None:
    parser = build_parser()
    clarg = make_clarg(parser.parse_args([]))
    assert clarg["verbose"] is False
    assert clarg["base"] is False
    assert clarg["vector"] is None
    assert clarg["vulnerability"] is None


def test_make_clarg_vulnerability_flag() -> None:
    parser = build_parser()
    clarg = make_clarg(parser.parse_args(["--vulnerability", _BASE_VECTOR]))
    assert clarg["vulnerability"] == _BASE_VECTOR


def test_make_clarg_base_and_vector() -> None:
    parser = build_parser()
    clarg = make_clarg(parser.parse_args(["-b", _BASE_VECTOR]))
    assert clarg["base"] is True
    assert clarg["vector"] == _BASE_VECTOR


def test_validate_flags_base_without_vector_exits_2() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        _validate_flags(parser, _make_clarg(base=True, vector=None))
    assert exc.value.code == 2


def test_validate_flags_no_base_or_vulnerability_exits_1() -> None:
    with pytest.raises(SystemExit) as exc:
        _validate_flags(build_parser(), _make_clarg())
    assert exc.value.code == 1
