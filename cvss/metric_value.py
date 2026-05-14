#! /usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# LICENSE: MIT LICENSE
#
"""Metrics values used by CVSS."""

from dataclasses import dataclass
from typing import override


@dataclass(frozen=True)
class MetricValue:
    """A Metric can have several different MetricValues.

    Once created the MetricValue cannot be changed.
    """

    metric: str
    value: str
    number: float
    description: str

    @override
    def __str__(self) -> str:
        return self.value

    def __float__(self) -> float:
        return self.number
