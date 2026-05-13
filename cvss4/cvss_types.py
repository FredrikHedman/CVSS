"""Shared types for the CVSS v4.0 CLI."""

from typing import Protocol, TypedDict, runtime_checkable

from .metric import Metric


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

    def base_metrics(self) -> list[Metric]: ...
    def threat_metrics(self) -> list[Metric]: ...
    def environmental_metrics(self) -> list[Metric]: ...
    def supplemental_metrics(self) -> list[Metric]: ...

    @property
    def macro_vector(self) -> tuple[int, int, int, int, int, int]: ...
