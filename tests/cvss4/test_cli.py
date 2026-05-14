"""CLI integration tests for cvss4."""

import shutil
import subprocess

CVSS4 = shutil.which("cvss4") or "cvss4"

_LOG4SHELL = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
)
_BASE_ONLY = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)


def run(args: list[str]) -> tuple[str, int]:
    result = subprocess.run(
        [CVSS4, *args],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr, result.returncode


def test_help_long() -> None:
    out, code = run(["--help"])
    assert code == 0
    assert "cvss4" in out
    assert "--vulnerability" in out
    assert "--base" in out
    assert "defaults to Attacked" in out


def test_help_short() -> None:
    out, code = run(["-h"])
    assert code == 0
    assert "cvss4" in out


def test_version() -> None:
    out, code = run(["--version"])
    assert code == 0
    assert out.strip() != ""


def test_vulnerability_vector() -> None:
    out, code = run(["--vulnerability", _LOG4SHELL])
    assert code == 0
    assert "CVSS-BT Score = 9.3" in out   # E:A present → BT label
    assert "Severity = Critical" in out
    assert "CVSS v4.0 Vulnerability Vector = " in out


def test_base_flag() -> None:
    out, code = run(["-b", _BASE_ONLY])
    assert code == 0
    assert "CVSS-B Score = 9.3" in out    # no threat/env → B label
    assert "Severity = Critical" in out


def test_verbose_flag_shows_groups() -> None:
    out, code = run(["-v", "--vulnerability", _BASE_ONLY])
    assert code == 0
    assert "BASE METRICS" in out
    assert "THREAT METRICS" in out
    assert "MacroVector EQ:" in out
    assert "CVSS-B Score = " in out


def test_bad_vector_exits_nonzero() -> None:
    _, code = run(["--vulnerability", "BAD:VECTOR"])
    assert code != 0


def test_base_without_vector_exits_2() -> None:
    _, code = run(["--base"])
    assert code == 2


def test_no_args_prints_usage() -> None:
    out, code = run([])
    assert code == 1
    assert "usage:" in out


def test_interactive_flag_unknown() -> None:
    _, code = run(["-i"])
    assert code != 0
