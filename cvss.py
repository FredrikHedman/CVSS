#!/usr/bin/env python3
"""
Calculate CVSS metrics based on a list of Metrics.

>>> from metric_value import MetricValue
>>> from metric import Metric
>>>
>>> m1 = MetricValue("Local", "L", 0.395, "A vulnerability exploitable with only local access")
>>> m2 = MetricValue("Adjecent Network", "A", 0.646, "A vulnerability exploitable with adjacent network access")
>>> m3 = MetricValue("Network", "N", 1.0, "A vulnerability exploitable with network access")
>>> avm = [m1, m2, m3]
>>> av = Metric("Access Vector", "AV", avm, 0)
>>>
>>> m1 = MetricValue("High", "H", 0.35, "Specialized access conditions exist")
>>> m2 = MetricValue("Medium", "M", 0.61, "The access conditions are somewhat specialized")
>>> m2 = MetricValue("Low", "L", 0.71, "Specialized access conditions or extenuating circumstances do not exist")
>>> avm = [m1, m2, m3]
>>> ac = Metric("Access Complexity", "AC", avm, 0)
>>>
>>> m1 = MetricValue("Multiple", "M", 0.45, "Exploit requires that the attacker authenticate two or more times")
>>> m2 = MetricValue("Single", "S", 0.56, "Exploit requires an attacker to be logged into the system")
>>> m3 = MetricValue("None", "N", 0.704, "Authentication is not required to exploit the vulnerability")
>>> avm = [m1, m2, m3]
>>> au = Metric("Authentication", "Au", avm, 0)
>>>
>>> exploitability = 20 * float(av.value) * float(ac.value) * float(au.value)
>>> exploitability
1.24425
>>> lmetrics = [ av, ac, au ]
>>> cvs = CommonVulnerabilityScore(lmetrics)
>>> print(cvs.exploitability)
1.24425
"""

class CommonVulnerabilityScore:

    def __init__(self, metrics_seq):
        self.metrics = {}
        for m in metrics_seq:
            self.metrics[m.short_name] = m

    @property
    def exploitability(self):
        res = 20.0
        res *= float(self.metrics['AV'].value)
        res *= float(self.metrics['AC'].value)
        res *= float(self.metrics['Au'].value)
        return res


if __name__ == "__main__":
    import doctest
    doctest.testmod()
