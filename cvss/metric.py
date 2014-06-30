#! /usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
from collections import OrderedDict
from .metric_value import MetricValue


class Metric(object):

    """Metrics used by CVSS."""

    def __init__(self, name, short_name, metric_values, index=None):
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
        if index is None:
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
        """Use selected MetricValue as a string."""
        return str(self.selected)

    def __float__(self):
        """Use selected MetricValue as a float."""
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
