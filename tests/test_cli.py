"""Unit tests for the argparse-based CLI in cvss.cvss."""

from unittest.mock import patch

import pytest

from cvss.cvss import build_parser, process_cmd_line_base, process_cmd_line_vulnerability
from cvss.cvss_types import CvssArgs


def test_no_args_shows_usage(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args([])
    clarg = vars(args)
    assert not (
        clarg["interactive"] or clarg["base"] or clarg["vulnerability"]
    )


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        _ = parser.parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "2.0.0" in captured.out


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        _ = parser.parse_args(["--help"])
    assert exc.value.code == 0


def test_base_flag_parsed() -> None:
    parser = build_parser()
    _args = parser.parse_args(["--base", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    clarg: CvssArgs = {
        "verbose": _args.verbose, "interactive": _args.interactive,
        "all": _args.all, "base": _args.base, "temporal": _args.temporal,
        "environmental": _args.environmental, "vector": _args.vector,
        "vulnerability": _args.vulnerability,
    }
    assert clarg["base"] is True
    assert clarg["vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_vulnerability_flag_parsed() -> None:
    parser = build_parser()
    _args = parser.parse_args(["--vulnerability", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    clarg: CvssArgs = {
        "verbose": _args.verbose, "interactive": _args.interactive,
        "all": _args.all, "base": _args.base, "temporal": _args.temporal,
        "environmental": _args.environmental, "vector": _args.vector,
        "vulnerability": _args.vulnerability,
    }
    assert clarg["vulnerability"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_verbose_short_flag() -> None:
    parser = build_parser()
    _args = parser.parse_args(["-v", "--base", "AV:L/AC:H/Au:N/C:N/I:N/A:N"])
    clarg: CvssArgs = {
        "verbose": _args.verbose, "interactive": _args.interactive,
        "all": _args.all, "base": _args.base, "temporal": _args.temporal,
        "environmental": _args.environmental, "vector": _args.vector,
        "vulnerability": _args.vulnerability,
    }
    assert clarg["verbose"] is True


def test_interactive_combined_flags() -> None:
    parser = build_parser()
    _args = parser.parse_args(["-ib"])
    clarg: CvssArgs = {
        "verbose": _args.verbose, "interactive": _args.interactive,
        "all": _args.all, "base": _args.base, "temporal": _args.temporal,
        "environmental": _args.environmental, "vector": _args.vector,
        "vulnerability": _args.vulnerability,
    }
    assert clarg["interactive"] is True
    assert clarg["base"] is True


def test_unexpected_exception_propagates() -> None:
    """Unexpected exceptions must NOT be swallowed by process_cmd_line_base."""
    clarg: CvssArgs = {
        "verbose": False, "interactive": False, "all": False,
        "base": True, "temporal": False, "environmental": False,
        "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "vulnerability": None,
    }
    exc_to_raise = RuntimeError("oops")
    with patch("cvss.cvss.VulnerabilityVector", side_effect=exc_to_raise):
        with pytest.raises(RuntimeError, match="oops"):
            _ = process_cmd_line_base(clarg)


def test_vulnerability_bad_vector_exits(capsys: pytest.CaptureFixture[str]) -> None:
    """Bad --vulnerability vector must print error and exit 1."""
    clarg: CvssArgs = {
        "verbose": False, "interactive": False, "all": False,
        "base": False, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": "BAD:VECTOR",
    }
    with pytest.raises(SystemExit) as exc:
        _ = process_cmd_line_vulnerability(clarg)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out != ""


def test_unexpected_exception_propagates_vulnerability() -> None:
    """Unexpected exceptions must NOT be swallowed by process_cmd_line_vulnerability."""
    clarg: CvssArgs = {
        "verbose": False, "interactive": False, "all": False,
        "base": False, "temporal": False, "environmental": False,
        "vector": None, "vulnerability": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    }
    exc_to_raise = RuntimeError("oops")
    with patch("cvss.cvss.VulnerabilityVector", side_effect=exc_to_raise):
        with pytest.raises(RuntimeError, match="oops"):
            _ = process_cmd_line_vulnerability(clarg)


@pytest.mark.parametrize("flag", ["-it", "-ite"])
def test_temporal_without_base_rejected(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = build_parser()
    args = parser.parse_args([flag])
    clarg = vars(args)
    with pytest.raises(SystemExit) as exc:
        if clarg["temporal"] and not clarg["base"]:
            parser.error("--temporal requires --base in interactive mode")
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--temporal requires --base" in captured.err


@pytest.mark.parametrize("flag", ["-ie", "-ibe"])
def test_environmental_without_temporal_rejected(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = build_parser()
    args = parser.parse_args([flag])
    clarg = vars(args)
    with pytest.raises(SystemExit) as exc:
        if clarg["environmental"] and not (
            clarg["base"] and clarg["temporal"]
        ):
            parser.error(
                "--environmental requires --base and --temporal"
                + " in interactive mode"
            )
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--environmental requires" in captured.err
