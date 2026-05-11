#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Shared type definitions for the cvss CLI."""

from typing import NamedTuple, Protocol, TypedDict

from .metric import Metric


class ScoreEntry(NamedTuple):
    """One score label, numeric value, and vulnerability vector."""

    name: str
    value: float
    vector: str


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
    cvss_version: str


class CVSSResult(Protocol):
    """Common interface satisfied by both v2.10 and v4.0 scorers."""

    @property
    def version(self) -> str: ...

    @property
    def base_score(self) -> float: ...

    @property
    def base_vulnerability_vector(self) -> str: ...

    def base_metrics(self) -> list[Metric]: ...
