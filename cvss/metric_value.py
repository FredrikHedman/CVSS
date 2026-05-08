#! /usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
"""Metrics values used by CVSS."""


class MetricValue:
    """A Metric can have several different MetricValues.

    Once created the MetricValue can not be changed.

    """

    def __init__(
        self,
        metric: str,
        value: str,
        number: float,
        description: str,
    ) -> None:
        self.__metric = metric
        self.__value = value
        self.__number = number
        self.__description = description

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}('{self.metric}','{self.value}',"
            f"{self.number},'{self.description}')"
        )

    def __str__(self) -> str:
        return self.value

    def __float__(self) -> float:
        return self.number

    @property
    def metric(self) -> str:
        return self.__metric

    @property
    def value(self) -> str:
        return self.__value

    @property
    def number(self) -> float:
        return self.__number

    @property
    def description(self) -> str:
        return self.__description


if __name__ == "__main__":
    import doctest

    doctest.testmod()
