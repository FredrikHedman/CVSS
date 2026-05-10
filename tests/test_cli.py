"""Unit tests for the argparse-based CLI in cvss.cvss."""

from unittest.mock import patch

import pytest

from cvss.cvss import main
from cvss.cvss_handlers import (
    process_cmd_line_base,
    process_cmd_line_vulnerability,
)
from cvss.cvss_parser import build_parser, make_clarg


def test_no_args_shows_usage(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args([])
    clarg = vars(args)
    assert not (
        clarg["interactive"] or clarg["base"] or clarg["vulnerability"]
    )


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    from importlib.metadata import version
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        _ = parser.parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert version("cvss") in captured.out


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        _ = parser.parse_args(["--help"])
    assert exc.value.code == 0


def test_base_flag_parsed() -> None:
    parser = build_parser()
    clarg = make_clarg(
        parser.parse_args(["--base", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    )
    assert clarg["base"] is True
    assert clarg["vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_vulnerability_flag_parsed() -> None:
    parser = build_parser()
    clarg = make_clarg(
        parser.parse_args(["--vulnerability", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    )
    assert clarg["vulnerability"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_verbose_short_flag() -> None:
    parser = build_parser()
    clarg = make_clarg(
        parser.parse_args(["-v", "--base", "AV:L/AC:H/Au:N/C:N/I:N/A:N"])
    )
    assert clarg["verbose"] is True


def test_interactive_combined_flags() -> None:
    parser = build_parser()
    clarg = make_clarg(parser.parse_args(["-ib"]))
    assert clarg["interactive"] is True
    assert clarg["base"] is True


def test_unexpected_exception_propagates() -> None:
    """Unexpected exceptions must NOT be swallowed by process_cmd_line_base."""
    exc_to_raise = RuntimeError("oops")
    with patch(
        "cvss.cvss_handlers.VulnerabilityVector", side_effect=exc_to_raise
    ):
        with pytest.raises(RuntimeError, match="oops"):
            _ = process_cmd_line_base("AV:N/AC:L/Au:N/C:C/I:C/A:C")


def test_vulnerability_bad_vector_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bad --vulnerability vector must print error and exit 1."""
    with pytest.raises(SystemExit) as exc:
        _ = process_cmd_line_vulnerability("BAD:VECTOR")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out != ""


def test_unexpected_exception_propagates_vulnerability() -> None:
    """Unexpected exceptions must NOT be swallowed by process_cmd_line_vulnerability."""  # noqa: E501
    exc_to_raise = RuntimeError("oops")
    with patch(
        "cvss.cvss_handlers.VulnerabilityVector", side_effect=exc_to_raise
    ):
        with pytest.raises(RuntimeError, match="oops"):
            _ = process_cmd_line_vulnerability("AV:N/AC:L/Au:N/C:C/I:C/A:C")


def test_base_requires_vector(capsys: pytest.CaptureFixture[str]) -> None:
    """cvss --base without a vector must exit 2 with an error message."""
    with patch("sys.argv", ["cvss", "--base"]):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--base requires a vector argument" in captured.err


@pytest.mark.parametrize("flag", ["-it", "-ite"])
def test_temporal_without_base_rejected(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("sys.argv", ["cvss", flag]):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--temporal requires --base" in captured.err


@pytest.mark.parametrize("flag", ["-ie", "-ibe"])
def test_environmental_without_temporal_rejected(
    flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("sys.argv", ["cvss", flag]):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--environmental requires" in captured.err
