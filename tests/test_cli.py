"""Unit tests for the argparse-based CLI in cvss.cvss."""

from typing import cast
from unittest.mock import patch

import pytest

from cvss.cvss import build_parser, process_cmd_line_base
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
    clarg = cast(CvssArgs, vars(
        parser.parse_args(["--base", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    ))
    assert clarg["base"] is True
    assert clarg["vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_vulnerability_flag_parsed() -> None:
    parser = build_parser()
    clarg = cast(CvssArgs, vars(
        parser.parse_args(["--vulnerability", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    ))
    assert clarg["vulnerability"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_verbose_short_flag() -> None:
    parser = build_parser()
    clarg = cast(CvssArgs, vars(
        parser.parse_args(["-v", "--base", "AV:L/AC:H/Au:N/C:N/I:N/A:N"])
    ))
    assert clarg["verbose"] is True


def test_interactive_combined_flags() -> None:
    parser = build_parser()
    clarg = cast(CvssArgs, vars(parser.parse_args(["-ib"])))
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
