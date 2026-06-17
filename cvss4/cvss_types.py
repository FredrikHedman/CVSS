"""Shared types for the CVSS v4.0 CLI."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypedDict, runtime_checkable

if TYPE_CHECKING:
    from .cvss_40 import EQLevels


@dataclass(frozen=True)
class MetricDisplay:
    """One row in a verbose metric group table."""

    name: str
    value: str
    abbrev: str


class CvssArgs(TypedDict):
    """Typed view of the argparse Namespace for the cvss4 CLI."""

    verbose: bool
    base: bool
    vector: str | None
    vulnerability: str | None


@runtime_checkable
class CVSS40Result(Protocol):
    """Interface satisfied by the CVSS v4.0 scorer."""

    @property
    def version(self) -> str: ...

    @property
    def base_score(self) -> float: ...

    @property
    def base_vulnerability_vector(self) -> str: ...

    def base_metrics(self) -> list[MetricDisplay]: ...
    def threat_metrics(self) -> list[MetricDisplay]: ...
    def environmental_metrics(self) -> list[MetricDisplay]: ...
    def supplemental_metrics(self) -> list[MetricDisplay]: ...

    @property
    def macro_vector(self) -> "EQLevels": ...
