#! /usr/bin/env python3
#
"""Metrics used by CVSS."""

from metric_value import MetricValue

class Metric:
    """
    >>> from metric_value import MetricValue
    >>> values = [ MetricValue('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), \
                   MetricValue('Single', 'S', 2.12, 'The vulnerability requires...'), ]
    >>> m = Metric("Authentication", values, 1)
    >>> m.name
    'Authentication'
    >>> m.values
    [MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')]
    >>> m.index = 4
    Traceback (most recent call last):
    ...
    AssertionError: must be in range [0, 2[
    >>> m.index = 1
    >>> m.selected
    MetricValue('Single','S',2.12,'The vulnerability requires...')
    >>> print(m.selected)
    S
    >>> float(m)
    2.12
    >>> print(m)
    S
    >>> repr(m)
    "Metric('Authentication',[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')],1)"
    """
    def __init__(self, name, metric_values, index = 0):
        self.__name = name
        vals = []
        for x in metric_values:
            if isinstance(x, MetricValue):
                vals.append(x)
            else:
                vals.append(MetricValue(*x))
        self.__values = tuple(vals)
        self.index = index

    def __repr__(self):
        return ("{0}('{1}',{2},{3})".format(self.__class__.__name__,
                                                  self.name,
                                                  self.values,
                                                  self.index))

    def __str__(self):
        "Use selected MetricValue as a string"
        return str(self.selected)

    def __float__(self):
        "Use selected MetricValue as a float"
        return float(self.selected)

    @property
    def name(self):
        return self.__name

    @property
    def values(self):
        return list(self.__values)

    @property
    def index(self):
        return self.__index

    @index.setter
    def index(self, index):
        L = len(self.__values)
        assert 0 <= index < L, "must be in range [{0}, {1}[".format(0,L)
        self.__index = index

    @property
    def selected(self):
        return self.__values[self.__index]


if __name__ == "__main__":
    import doctest
    doctest.testmod()

