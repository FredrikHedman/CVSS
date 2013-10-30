#!/usr/bin/env python3
#
"""
Calculate CVSS metrics based on a list of Metrics.
"""

from collections import defaultdict

class CommonVulnerabilityScore:
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



    @property
    def vulnerability_vector(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        vstr = []
        for v in vv:
            vstr.append(str(self.metrics[v]))
        return '/'.join(vstr)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
