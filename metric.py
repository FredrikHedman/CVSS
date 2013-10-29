#! /usr/bin/env python3
#
"""Metrics used by CVSS.

>>> from metric_value import MetricValue
>>> values = [ MetricValue('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), \
                   MetricValue('Single', 'S', 2.12, 'The vulnerability requires...'), \
                   MetricValue('None', 'N', 3.13, 'Authentication is not required...'), ]
>>> m = Metric("Authentication", "Au", values, 1)
>>> m.name
'Authentication'
>>> m.short_name
'Au'
>>> m.values
[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...'), MetricValue('None','N',3.13,'Authentication is not required...')]
>>> m.selection = 4
Traceback (most recent call last):
...
AssertionError: not in range
>>> m.selection = 1
>>> m.value
MetricValue('Single','S',2.12,'The vulnerability requires...')
>>> print(m.value)
S
>>> float(m.value)
2.12
"""

class Metric:
    def __init__(self, name, short_name, metric_values, index = 0):
        self.__name = name
        self.__abbr = short_name
        self.__values = tuple(metric_values)
        self.selection = index

    @property
    def value(self):
        return self.__values[self.__index]

    @property
    def selection(self):
        return self.__index

    @value.setter
    def selection(self, value):
        assert 0 <= value < len(self.__values), "not in range"
        self.__index = value

    @property
    def name(self):
        return self.__name

    @property
    def short_name(self):
        return self.__abbr

    @property
    def values(self):
        return list(self.__values)


if __name__ == "__main__":
    import doctest
    doctest.testmod()

