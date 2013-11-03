#!/usr/bin/env python3
#
"""
Calculate CVSS metrics v 2.10.
"""
from cvss_base import CVSS

class CommonVulnerabilityScore(CVSS):
    def __init__(self, metrics_seq):
        self.__metrics = {}
        for m in metrics_seq:
            self.__metrics[m.short_name] = m
        assert len(self.__metrics) == len(metrics_seq), 'Metric short name collision'

    def __getitem__(self, idx):
        return self.__metrics[idx]

    def base_metrics(self):
        return list
    @property
    def version(self):
        return "2.10"

    def base_fcn(self, impact):
        score = (0.6*impact + 0.4*self.exploitability - 1.5)
        score *= self.fcn(impact)
        return score

    def temporal_fcn(self, score):
        score *= float(self['E'])
        score *= float(self['RL'])
        score *= float(self['RC'])
        return score

    def environmental_fcn(self, adjusted_temporal_score):
        score = adjusted_temporal_score
        score += (10.0 - adjusted_temporal_score)*float(self['CDP'])
        score *= float(self['TD'])
        return score

    @property
    def impact(self):
        ConfImpact = float(self['C'])
        IntegImpact = float(self['I'])
        AvailImpact = float(self['A'])
        return self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)

    @property
    def adjusted_impact(self):
        ConfImpact = float(self['C']) * float(self['CR'])
        IntegImpact = float(self['I']) * float(self['IR'])
        AvailImpact = float(self['A']) * float(self['AR'])
        result = self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)
        return min(10.0, result)

    @property
    def exploitability(self):
        res = 20.0
        res *= float(self['AV'])
        res *= float(self['AC'])
        res *= float(self['Au'])
        return res

    def impact_fcn(self, conf_impact, integ_impact, avail_impact):
        result = 1 - (1-conf_impact)*(1-integ_impact)*(1-avail_impact)
        result *= 10.41
        return result

    def fcn(self, impact):
        val = 1.176
        if impact == 0:
            val = 0.0
        return val

    def base_metrics(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        ll = [self[v] for v in vv]
        return ll

    @property
    def base_vector(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)

    def temporal_metrics(self):
        vv = ['E', 'RL', 'RC']
        ll = [self[v] for v in vv]
        return ll

    @property
    def temporal_vector(self):
        vv = ['E', 'RL', 'RC']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)

    def environmental_metrics(self):
        vv = ['CDP', 'TD', 'CR', 'IR', 'AR']
        ll = [self[v] for v in vv]
        return ll

    @property
    def environmental_vector(self):
        vv = ['CDP', 'TD', 'CR', 'IR', 'AR']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
