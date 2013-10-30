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
    >>> m.choice = 4
    Traceback (most recent call last):
    ...
    AssertionError: must be in range [0, 2[
    >>> m.choice = 1
    >>> m.values[m.choice]
    MetricValue('Single','S',2.12,'The vulnerability requires...')
    >>> print(m.values[m.choice])
    S
    >>> float(m)
    2.12
    >>> print(m)
    Au:S
    >>> repr(m)
    "Metric('Authentication','Au',[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')],1)"
    """
    def __init__(self, name, short_name, metric_values, choice = 0):
        self.__name = name
        self.__abbr = short_name
        self.__values = tuple(metric_values)
        self.choice = choice

    def __str__(self):
        return "{0}:{1}".format(self.short_name, self.__values[self.choice])

    def __repr__(self):
        return ("{0}('{1}','{2}',{3},{4})".format(self.__class__.__name__,
                                                  self.name,
                                                  self.short_name,
                                                  self.values,
                                                  self.choice))

    def __float__(self):
        return float(self.__values[self.choice])

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
    def choice(self):
        return self.__choice

    @choice.setter
    def choice(self, choice):
        L = len(self.__values)
        assert 0 <= choice < L, "must be in range [{0}, {1}[".format(0,L)
        self.__choice = choice


if __name__ == "__main__":
    import doctest
    doctest.testmod()

