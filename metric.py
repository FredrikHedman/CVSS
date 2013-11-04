#! /usr/bin/env python3
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.1
# LICENSE: MIT LICENSE
#
"""Metrics used by CVSS.

>>> from metric_value import MetricValue
>>> values = ["Authentication", "Au", [('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), ], 'X' ]
>>> m = Metric(*values)
Traceback (most recent call last):
...
AssertionError: Not a valid key
>>> values = ["Authentication", "Au", [('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), ]]
>>> m = Metric(*values)
>>> m.index
'M'
>>> values = ["Authentication", "Au", [ ], 'S' ]
>>> m = Metric(*values)
Traceback (most recent call last):
...
AssertionError: At least one MetricValue needed.
>>> values = ["Authentication", "Au", [ ('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), \
                                   ('Single', 'S', 2.12, 'The vulnerability requires...'), ], \
              'S' \
             ]
>>> m = Metric(*values)
>>> m.name
'Authentication'
>>> m.values
[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')]
>>> m.index = 4
Traceback (most recent call last):
...
AssertionError: Not a valid key
>>> m.index = 'S'
>>> m.selected
MetricValue('Single','S',2.12,'The vulnerability requires...')
>>> print(m.selected)
S
>>> float(m.selected)
2.12
>>> float(m)
2.12
>>> print(m)
S
>>> repr(m)
"Metric('Authentication','Au',[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')],'S')"
"""
from collections import OrderedDict
from metric_value import MetricValue


class Metric:
    def __init__(self, name, short_name, metric_values, index = None):
        assert len(metric_values), 'At least one MetricValue needed.'
        self.__name = name
        self.__short_name = short_name
        # Create the key-value pairs. Use the MetricValue as the key.
        vals = []
        for x in metric_values:
            m = MetricValue(*x)
            vals.append((m.value, m))
        self.__values = OrderedDict(vals)
        # Use the first key available.
        if index == None:
            self.index = vals[0][0]
        else:
            assert index in self.__values.keys(), 'Not a valid key'
            self.index = index

    def __repr__(self):
        return ("{0}('{1}','{2}',{3},'{4}')".format(self.__class__.__name__,
                                                  self.name,
                                                  self.short_name,
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
    def short_name(self):
        return self.__short_name

    @property
    def values(self):
        return list(self.__values.values())

    @property
    def index(self):
        return self.__index

    @index.setter
    def index(self, index):
        assert index in self.__values.keys(), "Not a valid key"
        self.__index = index

    @property
    def selected(self):
        return self.__values[self.__index]


if __name__ == "__main__":
    import doctest
    doctest.testmod()

