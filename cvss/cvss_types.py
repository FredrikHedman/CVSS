#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Shared type definitions for the cvss CLI."""

from typing import TypedDict


class CvssArgs(TypedDict):
    """Typed view of the argparse Namespace for the cvss CLI."""

    verbose: bool
    interactive: bool
    all: bool
    base: bool
    temporal: bool
    environmental: bool
    vector: str | None
    vulnerability: str | None
