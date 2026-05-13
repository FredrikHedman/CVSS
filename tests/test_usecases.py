"""Use-case integration tests, replacing the shell scripts in this directory."""  # noqa: E501

import shutil
import subprocess
from pathlib import Path

TESTS_DIR = Path(__file__).parent
CVSS = shutil.which("cvss") or "cvss"


def run(args: list[str], stdin_file: Path | None = None) -> str:
    """Run cvss with *args*, optionally feeding *stdin_file* as stdin.

    Returns combined stdout+stderr as a string.
    """
    stdin = open(stdin_file) if stdin_file else None
    result = subprocess.run(
        [CVSS, *args],
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


def test_uc01_no_args():
    assert run([]) == expected("test_uc01a.txt")


def test_uc01_help_long():
    assert run(["--help"]) == expected("test_uc01b.txt")


def test_uc01_help_short():
    assert run(["-h"]) == expected("test_uc01b.txt")


# ---------------------------------------------------------------------------
# UC02 – interactive base scoring
# ---------------------------------------------------------------------------


def test_uc02_interactive_base():
    out = run(
        ["-ib", "--cvss-version", "v2"],
        stdin_file=TESTS_DIR / "test_uc02_in.txt",
    )
    assert out == expected("test_uc02_out.txt")


def test_uc02_interactive_base_verbose():
    out = run(
        ["-ivb", "--cvss-version", "v2"],
        stdin_file=TESTS_DIR / "test_uc02_in.txt",
    )
    assert out == expected("test_uc02_verbose_out.txt")


# ---------------------------------------------------------------------------
# UC03 – error cases and extended scoring (base / temporal / environmental)
# ---------------------------------------------------------------------------


_V2 = ["--cvss-version", "v2"]


def test_uc03_bad_key():
    assert run(["-ib", *_V2, "a:b/c:d"]) == expected(
        "test_uc03_bad_key_out2.txt"
    )


def test_uc03_empty_key():
    assert run(["-ib", *_V2, "a:b/:d"]) == expected(
        "test_uc03_bad_key_out2.txt"
    )


def test_uc03_empty_value():
    assert run(["-ib", *_V2, "a:/c:d"]) == expected(
        "test_uc03_bad_key_out2.txt"
    )


def test_uc03_empty_component():
    assert run(["-ib", *_V2, "a:b//c:d"]) == expected(
        "test_uc03_empty_out.txt"
    )


def test_uc03_bad_value():
    assert run(["-ib", *_V2, "AV:A/AC:M/Au:M/C:P/I:P/A:X"]) == expected(
        "test_uc03_bad_value_out.txt"
    )


def test_uc03_not_enough_keys():
    assert run(["-ib", *_V2, "AV:A/AC:M/Au:M/C:P/I:P"]) == expected(
        "test_uc03_not_enough_keys_out.txt"
    )


def test_uc03_duplicate_keys():
    assert run(["--base", "AV:A/AV:A/Au:S/C:C/I:P/A:C"]) == expected(
        "test_uc03_base_dup_out.txt"
    )


def test_uc03_bad_order():
    assert run(["-ib", *_V2, "AV:A/A:P/AC:M/Au:M/C:P/I:P"]) == expected(
        "test_uc03_bad_order_out.txt"
    )


def test_uc03_base_only():
    assert run(["--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"]) == expected(
        "test_uc03_base_out.txt"
    )


def test_uc03_temporal():
    out = run(
        ["-it", *_V2, "--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"],
        stdin_file=TESTS_DIR / "test_uc03_temporal_in.txt",
    )
    assert out == expected("test_uc03_temporal_out.txt")


def test_uc03_environmental():
    out = run(
        ["-ite", *_V2, "--base", "AV:A/AC:M/Au:S/C:C/I:P/A:C"],
        stdin_file=TESTS_DIR / "test_uc03_environmental_in.txt",
    )
    assert out == expected("test_uc03_environmental_out.txt")


# ---------------------------------------------------------------------------
# UC04 – same error cases as UC03 (duplicate coverage intentional)
# ---------------------------------------------------------------------------


def test_uc04_empty_end():
    assert run(["-ib", *_V2, "a:b/c:d/"]) == expected(
        "test_uc03_empty_end_out.txt"
    )


def test_uc04_bad_key():
    assert run(["-ib", *_V2, "a:b/c:d/"]) == expected(
        "test_uc03_bad_key_out.txt"
    )


# ---------------------------------------------------------------------------
# UC06 – interactive all-metrics regression test
# ---------------------------------------------------------------------------


def test_uc06_interactive_all():
    out = run(
        ["-ia", *_V2], stdin_file=TESTS_DIR / "test_uc06_in.txt"
    )
    assert out == expected("test_uc06_out.txt")


def test_uc06_interactive_all_verbose():
    out = run(
        ["-iav", *_V2], stdin_file=TESTS_DIR / "test_uc06_in.txt"
    )
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
