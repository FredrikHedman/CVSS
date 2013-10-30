#!/usr/bin/env python3
#
"""
Calculate CVSS metrics based on a list of Metrics.
"""

class CommonVulnerabilityScore:
    def __init__(self, metrics_seq):
        # A mapping from metric names to their short names used to
        # access them in the different algorithms.
        mapping = (("Access Vector", "AV"),
                   ("Access Complexity", "AC"),
                   ("Authentication", "Au"),
                   ("Confidentiality Impact", "C"),
                   ("Integrity Impact", "I"),
                   ("Availability Impact", "A"),
                   ("Exploitability", "E"),
                   ("Remediation Level", "RL"),
                   ("Report Confidence", "RC"),
                   ("Collateral Damage Potential", "CDP"),
                   ("Target Distribution", "TD"),
                   ("Confidentiality Requirement", "CR"),
                   ("Integrity Requirement", "IR"),
                   ("Availability Requirement", "AR"))
        short_name = dict(mapping)
        self.metrics = {}
        for m in metrics_seq:
            self.metrics[short_name[m.name]] = m

    @property
    def base_score(self):
        return round(self.base_fcn(self.impact), ndigits=1)

    @property
    def adjusted_base_score(self):
        return round(self.base_fcn(self.adjusted_impact), ndigits=1)

    @property
    def temporal_score(self):
        return round(self.temporal_fcn(self.base_score), ndigits=1)

    @property
    def adjusted_temporal_score(self):
        return round(self.temporal_fcn(self.adjusted_base_score), ndigits=1)

    @property
    def environmental_score(self):
        score = self.adjusted_temporal_score + (10.0 -
                self.adjusted_temporal_score)*float(self.metrics['CDP'])
        score *= float(self.metrics['TD'])
        return round(score, ndigits=1)

    @property
    def base_vulnerability_vector(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self.metrics[v])))
        return '/'.join(vstr)

    @property
    def temporal_vulnerability_vector(self):
        vv = ['E', 'RL', 'RC']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self.metrics[v])))
        return '/'.join(vstr)

    @property
    def environmental_vulnerability_vector(self):
        vv = ['CDP', 'TD', 'CR', 'IR', 'AR']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self.metrics[v])))
        return '/'.join(vstr)

    @property
    def exploitability(self):
        res = 20.0
        res *= float(self.metrics['AV'])
        res *= float(self.metrics['AC'])
        res *= float(self.metrics['Au'])
        return res

    @property
    def impact(self):
        ConfImpact = float(self.metrics['C'])
        IntegImpact = float(self.metrics['I'])
        AvailImpact = float(self.metrics['A'])
        return self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)

    @property
    def adjusted_impact(self):
        ConfImpact = float(self.metrics['C']) * float(self.metrics['CR'])
        IntegImpact = float(self.metrics['I']) * float(self.metrics['IR'])
        AvailImpact = float(self.metrics['A']) * float(self.metrics['AR'])
        result = self.impact_fcn(ConfImpact, IntegImpact, AvailImpact)
        return min(10.0, result)

    def fcn(self, impact):
        val = 1.176
        if impact == 0:
            val = 0.0
        return val

    def impact_fcn(self, conf_impact, integ_impact, avail_impact):
        result = 1 - (1-conf_impact)*(1-integ_impact)*(1-avail_impact)
        result *= 10.41
        return result

    def base_fcn(self, impact):
        score = (0.6*impact + 0.4*self.exploitability - 1.5)
        score *= self.fcn(impact)
        return score

    def temporal_fcn(self, score):
        score *= float(self.metrics['E'])
        score *= float(self.metrics['RL'])
        score *= float(self.metrics['RC'])
        return score


if __name__ == "__main__":
    import doctest
    doctest.testmod()
