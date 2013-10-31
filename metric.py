#! /usr/bin/env python3
#
"""Metrics used by CVSS."""
from collections import OrderedDict
from metric_value import MetricValue

def set_base_metrics(lmetrics, selected):
    base_metrics = [
    ["Access Vector",
     [("Local", "L", 0.395, "Local access"),
      ("Adjecent Network", "A", 0.646, "Adjacent network access"),
      ("Network", "N", 1.0, "Network access") ]],
    ["Access Complexity",
     [("High", "H", 0.35, "Specialized access conditions exist"),
       ("Medium", "M", 0.61, "The access conditions are somewhat specialized"),
       ("Low", "L", 0.71, "No specialized access exist") ]],
    ["Authentication",
     [("Multiple", "M", 0.45, "Authenticate two or more times"),
       ("Single", "S", 0.56, "Logged into the system"),
       ("None", "N", 0.704, "Authentication not required") ]],
    ["Confidentiality Impact",
     [("None", "N", 0.0, "No impact"),
       ("Partial", "P", 0.275, "Considerable disclosure"),
       ("Complete", "C", 0.660, "Total inforamtion disclosure") ]],
    ["Integrity Impact",
     [("None", "N", 0.0, "No impact"),
       ("Partial", "P", 0.275, "Possible to modify some system files or information"),
       ("Complete", "C", 0.660, "Total compromise of system integrity") ]],
    ["Availability Impact",
     [("None", "N", 0.0, "No impact"),
      ("Partial", "P", 0.275, "Reduced performance or interruptions in resource availability"),
      ("Complete", "C", 0.660, "Total shutdown of the affected resource") ]],
    ]
    for i, mm in enumerate(base_metrics):
        lmetrics.append(Metric(*mm, index = selected[0]))
        selected.pop(0)


def set_temporal_metrics(lmetrics, selected):
    temporal_metrics = [
    ["Exploitability",
     [("Unproven", "U", 0.85, "No exploit code is available"),
      ("Proof-of-Concept", "POC", 0.9, "Proof-of-concept exploit code exists"),
      ("Functional", "F", 0.95, "Functional exploit code is available"),
      ("High", "H", 1.0, "Exploitable by functional mobile autonomous code"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Remediation Level",
     [("Official Fix", "OF", 0.87, "Complete vendor solution is available"),
      ("Temporary Fix", "TF", 0.90, "Official but temporary fix available"),
      ("Workaround", "W", 0.95, "Unofficial, non-vendor solution available"),
      ("Unavailable", "U", 1.0, "No solution available or it is impossible to apply"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Report Confidence",
     [("Unconfirmed", "UC", 0.90, "Single unconfirmed source"),
      ("Uncorroborated", "UR", 0.95, "Multiple non-official sources"),
      ("Confirmed", "C", 1.0, "Acknowledged by the vendor or author"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ]
    for i, mm in enumerate(temporal_metrics):
        lmetrics.append(Metric(*mm, index = selected[0]))
        selected.pop(0)

def set_environmental_metrics(lmetrics, selected):
    environmental_metrics = [
    ["Collateral Damage Potential",
     [("None", "N", 0.0, "No potential for loss of life"),
      ("Low", "L", 0.1, "Potential for slight physical or property damage"),
      ("Low-Medium", "LM", 0.3, "Moderate physical or property damage"),
      ("Medium-High", "MH", 0.4, "Significant physical or property damage or loss"),
      ("High", "H", 0.5, "Catastrophic physical or property damage and loss"),
      ("Not Defined", "ND", 0.9, "Skip this metric") ]],
    ["Target Distribution",
     [("None", "N", 0.0, "No target systems exist"),
      ("Low", "L", 0.25, "Targets exist on a small scale inside the environment"),
      ("Medium", "M", 0.75, "Targets exist on a medium scale"),
      ("High", "H", 1.0, "Targets exist on a considerable scale"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Confidentiality Requirement",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Integrity Requirement",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Availability Requirement",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ]
    for i, mm in enumerate(environmental_metrics):
        lmetrics.append(Metric(*mm, index = selected[0]))
        selected.pop(0)

def cvs_factory(cls, selected = None):
    lmetrics = []
    if selected == None:
        selected = (6+3+5) * [0]
    else:
        selected.extend((6+3+5) * [0])
    set_base_metrics(lmetrics, selected)
    set_temporal_metrics(lmetrics, selected)
    set_environmental_metrics(lmetrics, selected)
    return cls(lmetrics)


class Metric:
    """
    >>> from metric_value import MetricValue
    >>> values = ["Authentication", [ ('Multiple', 'M', 1.11, 'Exploiting the vulnerability...'), \
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
    AssertionError
    >>> m.index = 'S'
    >>> m.selected
    MetricValue('Single','S',2.12,'The vulnerability requires...')
    >>> print(m.selected)
    S
    >>> float(m)
    2.12
    >>> print(m)
    S
    >>> repr(m)
    "Metric('Authentication',[MetricValue('Multiple','M',1.11,'Exploiting the vulnerability...'), MetricValue('Single','S',2.12,'The vulnerability requires...')],'S')"
    """
    def __init__(self, name, metric_values, index = None):
        self.__name = name
        vals = []
        for x in metric_values:
            m = MetricValue(*x)
            vals.append((m.value, m))
        self.__values = OrderedDict(vals)
        if index == None:
            self.index = vals[0][0]
        self.index = index

    def __repr__(self):
        return ("{0}('{1}',{2},'{3}')".format(self.__class__.__name__,
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
        return list(self.__values.values())

    @property
    def index(self):
        return self.__index

    @index.setter
    def index(self, index):
        assert index in self.__values.keys()
        self.__index = index

    @property
    def selected(self):
        return self.__values[self.__index]


if __name__ == "__main__":
    import doctest
    doctest.testmod()

