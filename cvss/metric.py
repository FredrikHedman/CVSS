#! /usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
from .metric_value import MetricValue


class Metric:
    """Metrics used by CVSS."""

    def __init__(
        self,
        name: str,
        short_name: str,
        metric_values: list[tuple[str, str, float, str]],
        index: str | None = None,
    ) -> None:
        if not metric_values:
            raise ValueError("At least one MetricValue needed.")
        self.__name = name
        self.__short_name = short_name
        # Create the key-value pairs. Use the MetricValue as the key.
        vals: list[tuple[str, MetricValue]] = []
        for x in metric_values:
            m = MetricValue(*x)
            vals.append((m.value, m))
        self.__values: dict[str, MetricValue] = dict(vals)
        # Use the first key available.
        if index is None:
            self.index = vals[0][0]
        else:
            if index not in self.__values:
                raise ValueError(f"{index!r} is not a valid index")
            self.index = index

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}('{self.name}','{self.short_name}',"
            f"{self.values},'{self.index}')"
        )

    def __str__(self) -> str:
        """Use selected MetricValue as a string."""
        return str(self.selected)

    def __float__(self) -> float:
        """Use selected MetricValue as a float."""
        return float(self.selected)

    @property
    def name(self) -> str:
        return self.__name

    @property
    def short_name(self) -> str:
        return self.__short_name

    @property
    def values(self) -> list[MetricValue]:
        return list(self.__values.values())

    @property
    def index(self) -> str:
        return self.__index

    @index.setter
    def index(self, index: str) -> None:
        if index not in self.__values:
            raise ValueError(f"{index!r} is not a valid index")
        self.__index = index

    @property
    def selected(self) -> MetricValue:
        return self.__values[self.__index]
