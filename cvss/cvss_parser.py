"""CVSS argument parsing and validation."""

import argparse
import sys
from importlib.metadata import version

from .cvss_types import CvssArgs

VERSION = version("cvss")


class _ParsedArgs(argparse.Namespace):
    verbose: bool = False
    interactive: bool = False
    all: bool = False
    base: bool = False
    temporal: bool = False
    environmental: bool = False
    vector: str | None = None
    vulnerability: str | None = None


def make_clarg(args: argparse.Namespace) -> CvssArgs:
    """Build a typed CvssArgs dict from an argparse Namespace."""
    typed: _ParsedArgs = args  # pyright: ignore[reportAssignmentType]
    return {
        "verbose": typed.verbose,
        "interactive": typed.interactive,
        "all": typed.all,
        "base": typed.base,
        "temporal": typed.temporal,
        "environmental": typed.environmental,
        "vector": typed.vector,
        "vulnerability": typed.vulnerability,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cvss",
        description="Calculate CVSS metrics based on a list of Metrics.",
    )
    _ = p.add_argument("-v", "--verbose", action="store_true")
    _ = p.add_argument("-i", "--interactive", action="store_true")
    _ = p.add_argument("-a", "--all", action="store_true", dest="all")
    _ = p.add_argument("-b", "--base", action="store_true")
    _ = p.add_argument("-t", "--temporal", action="store_true")
    _ = p.add_argument("-e", "--environmental", action="store_true")
    _ = p.add_argument("vector", nargs="?", default=None)
    _ = p.add_argument("--vulnerability", metavar="vector", default=None)
    _ = p.add_argument("--version", action="version", version=VERSION)
    return p


def _validate_flags(
    parser: argparse.ArgumentParser, clarg: CvssArgs
) -> None:
    if clarg["base"] and not clarg["interactive"] and clarg["vector"] is None:
        parser.error("--base requires a vector argument")
    if clarg["interactive"]:
        if clarg["temporal"] and not clarg["base"]:
            parser.error("--temporal requires --base in interactive mode")
        if clarg["environmental"] and not (
            clarg["base"] and clarg["temporal"]
        ):
            parser.error(
                "--environmental requires --base and --temporal"
                + " in interactive mode"
            )
    if not (clarg["interactive"] or clarg["base"] or clarg["vulnerability"]):
        parser.print_usage()
        sys.exit(1)


def parse_and_validate() -> CvssArgs:
    """Parse argv, validate flags, and return a typed argument dict."""
    parser = build_parser()
    clarg = make_clarg(parser.parse_args())
    _validate_flags(parser, clarg)
    if clarg["vulnerability"]:  # --vulnerability always shows all scores
        clarg["all"] = True
    return clarg
