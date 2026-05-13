"""CVSS v4.0 argument parsing and validation."""

import argparse
import sys
from importlib.metadata import version

from .cvss_types import CvssArgs

VERSION = version("cvss")


class _ParsedArgs(argparse.Namespace):
    verbose: bool = False
    base: bool = False
    vector: str | None = None
    vulnerability: str | None = None


def make_clarg(args: argparse.Namespace) -> CvssArgs:
    """Build a typed CvssArgs dict from an argparse Namespace."""
    typed: _ParsedArgs = args  # pyright: ignore[reportAssignmentType]
    return {
        "verbose": typed.verbose,
        "base": typed.base,
        "vector": typed.vector,
        "vulnerability": typed.vulnerability,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cvss4",
        description="Calculate CVSS v4.0 metrics.",
    )
    _ = p.add_argument("-v", "--verbose", action="store_true")
    _ = p.add_argument("-b", "--base", action="store_true")
    _ = p.add_argument("vector", nargs="?", default=None)
    _ = p.add_argument("--vulnerability", metavar="vector", default=None)
    _ = p.add_argument("--version", action="version", version=VERSION)
    return p


def _validate_flags(
    parser: argparse.ArgumentParser, clarg: CvssArgs
) -> None:
    if clarg["base"] and clarg["vector"] is None:
        parser.error("--base requires a vector argument")
    if not (clarg["base"] or clarg["vulnerability"]):
        parser.print_usage()
        sys.exit(1)


def parse_and_validate() -> CvssArgs:
    """Parse argv, validate flags, and return a typed argument dict."""
    parser = build_parser()
    clarg = make_clarg(parser.parse_args())
    _validate_flags(parser, clarg)
    return clarg
