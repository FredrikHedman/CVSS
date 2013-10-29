#! /usr/bin/env python3
#
"""Metrics used by CVSS."""

class Metric:
    """
    >>> from metric_value import MetricValue
    >>> values = [ MetricValue('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), \
                   MetricValue('Single', 'S', 2.12, 'The vulnerability requires...'), ]
    >>> m = Metric("Authentication", "Au", values, 1)
    >>> m.name
    'Authentication'
    >>> m.short_name
    'Au'
    >>> m.values
    [MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')]
    >>> m.value = 4
    Traceback (most recent call last):
    ...
    AssertionError: must be in range [0, 2[
    >>> m.value = 1
    >>> m.value
    MetricValue('Single','S',2.12,'The vulnerability requires...')
    >>> print(m.value)
    S
    >>> float(m.value)
    2.12
    >>> print(m)
    Au:S
    >>> repr(m)
    "Metric('Authentication','Au',[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')],'S')"
    """
    def __init__(self, name, short_name, metric_values, value = 0):
        self.__name = name
        self.__abbr = short_name
        self.__values = tuple(metric_values)
        self.value = value

    def __str__(self):
        return "{0}:{1}".format(self.short_name, self.value)

    def __repr__(self):
        return ("{0}('{1}','{2}',{3},'{4}')".format(self.__class__.__name__,
                                              self.name,
                                              self.short_name,
                                              self.values,
                                                    self.value))

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

