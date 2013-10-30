#!/usr/bin/env python3
#
from collections import defaultdict

class CommonVulnerabilityScore:
    """
    Calculate CVSS metrics based on a list of Metrics.

    >>> from metric_value import MetricValue
    >>> from metric import Metric
    >>> lmetrics = []
    >>> m1 = MetricValue("Local", "L", 0.395, "Local access")
    >>> m2 = MetricValue("Adjecent Network", "A", 0.646, "Adjacent network access")
    >>> m3 = MetricValue("Network", "N", 1.0, "Network access")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Access Vector", "AV", avm, 0))
    >>>
    >>> m1 = MetricValue("High", "H", 0.35, "Specialized access conditions exist")
    >>> m2 = MetricValue("Medium", "M", 0.61, "The access conditions are somewhat specialized")
    >>> m2 = MetricValue("Low", "L", 0.71, "No specialized access exist")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Access Complexity", "AC", avm, 0))
    >>>
    >>> m1 = MetricValue("Multiple", "M", 0.45, "Authenticate two or more times")
    >>> m2 = MetricValue("Single", "S", 0.56, "Logged into the system")
    >>> m3 = MetricValue("None", "N", 0.704, "Authentication not required")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Authentication", "Au", avm, 0))
    >>>
    >>> exploitability = 20
    >>> for x in lmetrics: exploitability *= float(x)
    >>> exploitability
    1.24425
    >>> cvs = CommonVulnerabilityScore(lmetrics)
    >>> print(cvs.exploitability)
    1.24425
    >>> print(cvs.impact)
    0.0
    >>> print(cvs.fcn(1.2, 'BaseScore'))
    1.176
    >>> print(cvs.base_score)
    -0.0
    >>> m1 = MetricValue("None", "N", 0.0, "No impact")
    >>> m2 = MetricValue("Partial", "P", 0.275, "Considerable disclosure")
    >>> m3 = MetricValue("Complete", "C", 0.660, "Total inforamtion disclosure")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Confidentiality Impact", "C", avm, 2))
    >>>
    >>> m1 = MetricValue("None", "N", 0.0, "No impact")
    >>> m2 = MetricValue("Partial", "P", 0.275, "Possible to modify some system files or information")
    >>> m3 = MetricValue("Complete", "C", 0.660, "Total compromise of system integrity")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Integrity Impact", "I", avm, 2))
    >>>
    >>> m1 = MetricValue("None", "N", 0.0, "No impact")
    >>> m2 = MetricValue("Partial", "P", 0.275, "Reduced performance or interruptions in resource availability")
    >>> m3 = MetricValue("Complete", "C", 0.660, "Total shutdown of the affected resource")
    >>> avm = [m1, m2, m3]
    >>> lmetrics.append(Metric("Availability Impact", "A", avm, 2))
    >>>
    >>> cvs = CommonVulnerabilityScore(lmetrics)
    >>> print(cvs.base_score)
    5.9
    """
    def __init__(self, metrics_seq):
        self.metrics = defaultdict(int)
        for m in metrics_seq:
            self.metrics[m.short_name] = m

    def fcn(self, impact, case):
        if case == 'BaseScore':
            if impact == 0:
                return 0.0
            else:
                return 1.176

    @property
    def impact(self):
        ConfImpact = float(self.metrics['C'])
        IntegImpact = float(self.metrics['I'])
        AvailImpact = float(self.metrics['A'])
        result = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
        return result

    @property
    def exploitability(self):
        res = 20.0
        res *= float(self.metrics['AV'])
        res *= float(self.metrics['AC'])
        res *= float(self.metrics['Au'])
        return res

    @property
    def base_score(self):
        score = (0.6*self.impact + 0.4*self.exploitability - 1.5)
        score *= self.fcn(self.impact, 'BaseScore') 
        return round(score, ndigits=1)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
