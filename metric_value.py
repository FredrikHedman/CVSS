#! /usr/bin/env python3
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.15
# LICENSE: MIT LICENSE
#
"""Metrics values used by CVSS."""


class MetricValue:
    """A Metric can have several different MetricValues.  Once created the
    MetricValue can not be changed.

    >>> m = MetricValue('Local', 'L', 1.2, 'A vulnerability')
    >>> repr(m)
    "MetricValue('Local','L',1.2,'A vulnerability')"
    >>> str(m)
    'L'
    >>> print(m)
    L
    >>> m.value
    'L'
    >>> 2.0 * float(m)
    2.4
    >>> m.metric
    'Local'
    >>> m.value
    'L'
    >>> m.number
    1.2
    >>> m.description
    'A vulnerability'
    >>> m.metric = 'another name'
    Traceback (most recent call last):
    ...
    AttributeError: can't set attribute
    >>> m.value = 'another value'
    Traceback (most recent call last):
    ...
    AttributeError: can't set attribute
    >>> m.number = 0.0
    Traceback (most recent call last):
    ...
    AttributeError: can't set attribute
    >>> m.description = 'a longer text'
    Traceback (most recent call last):
    ...
    AttributeError: can't set attribute
    """
    def __init__(self, metric, value, number, description):
        self.__metric = metric
        self.__value = value
        self.__number = number
        self.__description = description

    def __repr__(self):
        return ("{0}('{1}','{2}',{3},'{4}')".format(self.__class__.__name__,
                                                    self.metric,
                                                    self.value,
                                                    self.number,
                                                    self.description))

    def __str__(self):
        return self.value

    def __float__(self):
        return self.number

    @property
    def metric(self):
        return self.__metric

    @property
    def value(self):
        return self.__value

    @property
    def number(self):
        return self.__number

    @property
    def description(self):
        return self.__description


if __name__ == "__main__":
    import doctest
    doctest.testmod()
