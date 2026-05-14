#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
"""Base class for CVSS metrics."""

import abc

from cvss.metric import Metric


class CVSS(abc.ABC):
    """Abstract base class for CVSS score calculators.

    Subclasses must implement the scoring functions, metric accessors,
    and vector properties listed below.
    """

    # ------------------------------------------------------------------
    # Abstract: subclasses supply these
    # ------------------------------------------------------------------

    @property
    @abc.abstractmethod
    def version(self) -> str: ...

    @abc.abstractmethod
    def base_fcn(self, impact: float) -> float: ...

    @abc.abstractmethod
    def temporal_fcn(self, score: float) -> float: ...

    @abc.abstractmethod
    def environmental_fcn(self, adjusted_temporal_score: float) -> float: ...

    @property
    @abc.abstractmethod
    def impact(self) -> float: ...

    @property
    @abc.abstractmethod
    def adjusted_impact(self) -> float: ...

    @property
    @abc.abstractmethod
    def exploitability(self) -> float: ...

    @abc.abstractmethod
    def base_metrics(self) -> list[Metric]: ...

    @abc.abstractmethod
    def temporal_metrics(self) -> list[Metric]: ...

    @abc.abstractmethod
    def environmental_metrics(self) -> list[Metric]: ...

    @property
    @abc.abstractmethod
    def base_vector(self) -> str: ...

    @property
    @abc.abstractmethod
    def temporal_vector(self) -> str: ...

    @property
    @abc.abstractmethod
    def environmental_vector(self) -> str: ...

    # ------------------------------------------------------------------
    # Concrete: template-method properties built on the abstract ones
    # ------------------------------------------------------------------

    @property
    def base_score(self) -> float:
        return round(self.base_fcn(self.impact), ndigits=1)

    @property
    def adjusted_base_score(self) -> float:
        return round(self.base_fcn(self.adjusted_impact), ndigits=1)

    @property
    def temporal_score(self) -> float:
        return round(self.temporal_fcn(self.base_score), ndigits=1)

    @property
    def adjusted_temporal_score(self) -> float:
        return round(
            self.temporal_fcn(self.adjusted_base_score), ndigits=1
        )

    @property
    def environmental_score(self) -> float:
        return round(
            self.environmental_fcn(self.adjusted_temporal_score), ndigits=1
        )

    @property
    def base_vulnerability_vector(self) -> str:
        return self.base_vector

    @property
    def temporal_vulnerability_vector(self) -> str:
        return self.temporal_vector

    @property
    def environmental_vulnerability_vector(self) -> str:
        return self.environmental_vector
