#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Calculate CVSS metrics based on a list of Metrics."""

import argparse
import sys
from importlib.metadata import version

from .cvss_210 import CommonVulnerabilityScore
from .cvss_base import CVSS
from .cvss_interactive import (
    generate_output,
    generate_verbose_output,
    select_metric_value,
)
from .cvss_types import CvssArgs
from .vulnerability import (
    InvalidBaseVectorError,
    MetricDefinition,
    VulnerabilityVector,
    base_metrics,
    cvs_factory,
    environmental_metrics,
    temporal_metrics,
)

VERSION = version("cvss")


class _ParsedArgs(argparse.Namespace):
    verbose: bool
    interactive: bool
    all: bool
    base: bool
    temporal: bool
    environmental: bool
    vector: str | None
    vulnerability: str | None


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


def read_and_set(L: list[MetricDefinition], selected: list[str]) -> list[str]:
    """Read and set selected metrics."""
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)
    return selected


def process_cmd_line_interactive(clarg: CvssArgs) -> CVSS:
    selected: list[str] = []
    if clarg["base"]:
        if clarg["vector"]:
            try:
                vvec = VulnerabilityVector(clarg["vector"])
                selected.extend(vvec.valid().complete().metric_values())
            except (InvalidBaseVectorError, ValueError) as e:
                print(e)
                sys.exit(1)
        else:
            selected = read_and_set(base_metrics(), selected)
    if clarg["temporal"]:
        selected = read_and_set(temporal_metrics(), selected)
    if clarg["temporal"] and clarg["environmental"]:
        selected = read_and_set(environmental_metrics(), selected)
    if clarg["all"]:
        selected = read_and_set(base_metrics(), selected)
        selected = read_and_set(temporal_metrics(), selected)
        selected = read_and_set(environmental_metrics(), selected)
    cvs = cvs_factory(CommonVulnerabilityScore, selected)
    return cvs


def process_cmd_line_base(clarg: CvssArgs) -> CVSS:
    try:
        vector = clarg["vector"]
        if vector is None:
            raise ValueError("--base requires a vector argument")
        vvec = VulnerabilityVector(vector)
        cvs = cvs_factory(
            CommonVulnerabilityScore, vvec.valid().complete().metric_values()
        )
    except (InvalidBaseVectorError, ValueError) as e:
        print(e)
        sys.exit(1)
    return cvs


def process_cmd_line_vulnerability(clarg: CvssArgs) -> CVSS:
    vulnerability = clarg["vulnerability"]
    if vulnerability is None:
        raise ValueError("--vulnerability requires a vector argument")
    try:
        vvec = VulnerabilityVector(vulnerability)
        cvs = cvs_factory(
            CommonVulnerabilityScore, vvec.valid().metric_values()
        )
    except (InvalidBaseVectorError, ValueError) as e:
        print(e)
        sys.exit(1)
    return cvs


def process_cmd_line(clarg: CvssArgs) -> CVSS:
    """React to the command line."""
    if clarg["interactive"]:
        cvs = process_cmd_line_interactive(clarg)
    elif clarg["base"]:
        cvs = process_cmd_line_base(clarg)
    elif clarg["vulnerability"]:
        cvs = process_cmd_line_vulnerability(clarg)
    else:
        raise RuntimeError("unreachable")
    return cvs


def main() -> None:
    parser = build_parser()
    args: _ParsedArgs = parser.parse_args()  # type: ignore[assignment]
    clarg: CvssArgs = {
        "verbose": args.verbose,
        "interactive": args.interactive,
        "all": args.all,
        "base": args.base,
        "temporal": args.temporal,
        "environmental": args.environmental,
        "vector": args.vector,
        "vulnerability": args.vulnerability,
    }

    # Validate interactive-mode flag combinations.
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

    # No actionable flag provided → show usage.
    if not (clarg["interactive"] or clarg["base"] or clarg["vulnerability"]):
        parser.print_usage()
        sys.exit(1)

    cvs = process_cmd_line(clarg)

    # --vulnerability always shows all three scores
    if clarg["vulnerability"]:
        clarg["all"] = True

    if clarg["verbose"]:
        generate_verbose_output(cvs, clarg)
    else:
        generate_output(cvs, clarg)


if __name__ == "__main__":
    main()
