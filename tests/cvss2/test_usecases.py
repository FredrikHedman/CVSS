"""Use-case integration tests for cvss2."""

import shutil
import subprocess
from pathlib import Path

TESTS_DIR = Path(__file__).parent
CVSS2 = shutil.which("cvss2") or "cvss2"


def run(args: list[str], stdin_file: Path | None = None) -> str:
    """Run cvss2 with *args*, optionally feeding *stdin_file* as stdin."""
    stdin = open(stdin_file) if stdin_file else None
    result = subprocess.run(
        [CVSS2, *args],
        capture_output=True,
        text=True,
        stdin=stdin,
    )
    if stdin:
        stdin.close()
    return result.stdout + result.stderr


def expected(filename: str) -> str:
    return (TESTS_DIR / filename).read_text()


# ---------------------------------------------------------------------------
# UC01 – help / no-argument invocation
# ---------------------------------------------------------------------------


def test_uc01_no_args() -> None:
    assert run([]) == expected("test_uc01a.txt")


def test_uc01_help_long() -> None:
    assert run(["--help"]) == expected("test_uc01b.txt")


def test_uc01_help_short() -> None:
    assert run(["-h"]) == expected("test_uc01b.txt")


# ---------------------------------------------------------------------------
# UC02 – interactive base scoring
# ---------------------------------------------------------------------------


def test_uc02_interactive_base() -> None:
    out = run(
        ["-ib"],
        stdin_file=TESTS_DIR / "test_uc02_in.txt",
    )
    assert out == expected("test_uc02_out.txt")


def test_uc02_interactive_base_verbose() -> None:
    out = run(
        ["-ivb"],
        stdin_file=TESTS_DIR / "test_uc02_in.txt",
    )
    assert out == expected("test_uc02_verbose_out.txt")


# ---------------------------------------------------------------------------
# UC03 – error cases and extended scoring (base / temporal / environmental)
# ---------------------------------------------------------------------------


def test_uc03_bad_key() -> None:
    assert run(["-ib", "a:b/c:d"]) == expected("test_uc03_bad_key_out2.txt")


def test_uc03_empty_key() -> None:
    assert run(["-ib", "a:b/:d"]) == expected("test_uc03_bad_key_out2.txt")


def test_uc03_empty_value() -> None:
    assert run(["-ib", "a:/c:d"]) == expected("test_uc03_bad_key_out2.txt")


def test_uc03_empty_component() -> None:
    assert run(["-ib", "a:b//c:d"]) == expected("test_uc03_empty_out.txt")


def test_uc03_bad_value() -> None:
    assert run(["-ib", "AV:A/AC:M/Au:M/C:P/I:P/A:X"]) == expected(
        "test_uc03_bad_value_out.txt"
    )


def test_uc03_not_enough_keys() -> None:
    assert run(["-ib", "AV:A/AC:M/Au:M/C:P/I:P"]) == expected(
        "test_uc03_not_enough_keys_out.txt"
    )


def test_uc03_duplicate_keys() -> None:
    assert run(["--base", "AV:A/AV:A/Au:S/C:C/I:P/A:C"]) == expected(
        "test_uc03_base_dup_out.txt"
    )


def test_uc03_bad_order() -> None:
    assert run(["-ib", "AV:A/A:P/AC:M/Au:M/C:P/I:P"]) == expected(
        "test_uc03_bad_order_out.txt"
    )


def test_uc03_base_only() -> None:
    assert run(["--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"]) == expected(
        "test_uc03_base_out.txt"
    )


def test_uc03_temporal() -> None:
    out = run(
        ["-it", "--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"],
        stdin_file=TESTS_DIR / "test_uc03_temporal_in.txt",
    )
    assert out == expected("test_uc03_temporal_out.txt")


def test_uc03_environmental() -> None:
    out = run(
        ["-ite", "--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"],
        stdin_file=TESTS_DIR / "test_uc03_environmental_in.txt",
    )
    assert out == expected("test_uc03_environmental_out.txt")


# ---------------------------------------------------------------------------
# UC04 – same error cases as UC03 (duplicate coverage intentional)
# ---------------------------------------------------------------------------


def test_uc04_empty_end() -> None:
    assert run(["-ib", "a:b/c:d/"]) == expected("test_uc03_empty_end_out.txt")


def test_uc04_bad_key() -> None:
    assert run(["-ib", "a:b/c:d/"]) == expected("test_uc03_bad_key_out.txt")


# ---------------------------------------------------------------------------
# UC06 – interactive all-metrics regression test
# ---------------------------------------------------------------------------


def test_uc06_interactive_all() -> None:
    out = run(["-ia"], stdin_file=TESTS_DIR / "test_uc06_in.txt")
    assert out == expected("test_uc06_out.txt")


def test_uc06_interactive_all_verbose() -> None:
    out = run(["-iav"], stdin_file=TESTS_DIR / "test_uc06_in.txt")
    assert out == expected("test_uc06_verbose_out.txt")


# ---------------------------------------------------------------------------
# --vulnerability flag
# ---------------------------------------------------------------------------


def test_vulnerability_shows_all_scores() -> None:
    """--vulnerability must output all three score lines."""
    out = run(["--vulnerability", "AV:A/AC:M/Au:S/C:C/I:P/A:C"])
    assert "Base Score = " in out
    assert "Temporal Score = " in out
    assert "Environmental Score = " in out
