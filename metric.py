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
>>> m.value = 4
Traceback (most recent call last):
...
AssertionError: must be in range [0, 3[
>>> m.value = 1
>>> m.value
MetricValue('Single','S',2.12,'The vulnerability requires...')
>>> print(m.value)
S
>>> float(m.value)
2.12
"""

class Metric:
    def __init__(self, name, short_name, metric_values, value = 0):
        self.__name = name
        self.__abbr = short_name
        self.__values = tuple(metric_values)
        self.value = value

    @property
    def name(self):
        return self.__name

    @property
    def short_name(self):
        return self.__abbr

    @property
    def values(self):
        return list(self.__values)

    @property
    def value(self):
        return self.__values[self.__value]

    @value.setter
    def value(self, value):
        L = len(self.__values)
        assert 0 <= value < L, "must be in range [{0}, {1}[".format(0,L)
        self.__value = value


if __name__ == "__main__":
    import doctest
    doctest.testmod()

