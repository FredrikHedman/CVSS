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

    def fcn(self, impact):
        val = 1.176
        if impact == 0:
            val = 0.0
        return val

    def impact_fcn(self, conf_impact, integ_impact, avail_impact):
        result = 1 - (1-conf_impact)*(1-integ_impact)*(1-avail_impact)
        result *= 10.41
        return result

    @property
    def impact(self):
        ConfImpact = float(self.metrics['C'])
        IntegImpact = float(self.metrics['I'])
        AvailImpact = float(self.metrics['A'])
        return self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)

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
        score *= self.fcn(self.impact) 
        return round(score, ndigits=1)

    @property
    def vulnerability_vector(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        vstr = []
        for v in vv:
            vstr.append(str(self.metrics[v]))
        return '/'.join(vstr)



    @property
    def temporal_score(self):
        score = self.base_score
        score *= float(self.metrics['E'])
        score *= float(self.metrics['RL'])
        score *= float(self.metrics['RC'])
        return round(score, ndigits=1)

    @property
    def adjusted_impact(self):
        ConfImpact = float(self.metrics['C']) * float(self.metrics['CR'])
        IntegImpact = float(self.metrics['I']) * float(self.metrics['IR'])
        AvailImpact = float(self.metrics['A']) * float(self.metrics['AR'])
        result = self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)
        return min(10.0, result)

    @property

    def adjusted_base(self):
        score = (0.6*self.adjusted_impact + 0.4*self.exploitability - 1.5)
        score *= self.fcn(self.adjusted_impact)
        return round(score, ndigits=1)

    @property
    def adjusted_temporal(self):
        score = self.adjusted_base
        score *= float(self.metrics['E'])
        score *= float(self.metrics['RL'])
        score *= float(self.metrics['RC'])
        return round(score, ndigits=1)

    @property
    def environmental_score(self):
        score = self.adjusted_temporal + (10.0 - self.adjusted_temporal)*float(self.metrics['CDP'])
        score *= float(self.metrics['TD'])
        return round(score, ndigits=1)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
