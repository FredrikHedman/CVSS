#!/usr/bin/env python3
#
"""
Calculate CVSS metrics based on a list of Metrics.
"""

def cvs_factory():
    from metric_value import MetricValue
    from metric import Metric
    from cvss import CommonVulnerabilityScore
    lmetrics = []

    mvv = ["Access Vector", [("Local", "L", 0.395, "Local access"),
                             ("Adjecent Network", "A", 0.646, "Adjacent network access"),
                             ("Network", "N", 1.0, "Network access")]]
    lmetrics.append(Metric(*mvv))

    m1 = MetricValue("High", "H", 0.35, "Specialized access conditions exist")
    m2 = MetricValue("Medium", "M", 0.61,
                     "The access conditions are somewhat specialized")
    m3 = MetricValue("Low", "L", 0.71, "No specialized access exist")
    avm = [m1, m2, m3]
    lmetrics.append(Metric("Access Complexity", avm))

    m1 = MetricValue("Multiple", "M", 0.45, "Authenticate two or more times")
    m2 = MetricValue("Single", "S", 0.56, "Logged into the system")
    m3 = MetricValue("None", "N", 0.704, "Authentication not required")
    avm = [m1, m2, m3]
    lmetrics.append(Metric("Authentication", avm))

    m1 = MetricValue("None", "N", 0.0, "No impact")
    m2 = MetricValue("Partial", "P", 0.275, "Considerable disclosure")
    m3 = MetricValue("Complete", "C", 0.660, "Total inforamtion disclosure")
    avm = [m1, m2, m3]
    lmetrics.append(Metric("Confidentiality Impact", avm))

    m1 = MetricValue("None", "N", 0.0, "No impact")
    m2 = MetricValue("Partial", "P", 0.275,
                     "Possible to modify some system files or information")
    m3 = MetricValue("Complete", "C", 0.660,
                     "Total compromise of system integrity")
    avm = [m1, m2, m3]
    lmetrics.append(Metric("Integrity Impact", avm))

    m1 = MetricValue("None", "N", 0.0, "No impact")
    m2 = MetricValue("Partial", "P", 0.275,
                     "Reduced performance or interruptions in resource availability")
    m3 = MetricValue("Complete", "C", 0.660,
                     "Total shutdown of the affected resource")
    avm = [m1, m2, m3]
    lmetrics.append(Metric("Availability Impact", avm))

    m1 = MetricValue("Unproven", "U", 0.85, "No exploit code is available")
    m2 = MetricValue("Proof-of-Concept", "POC", 0.9,
                     "Proof-of-concept exploit code exists")
    m3 = MetricValue("Functional", "F", 0.95, "Functional exploit code is available")
    m4 = MetricValue("High", "H", 1.0,
                     "Exploitable by functional mobile autonomous code")
    m5 = MetricValue("Not Defined", "ND", 1.0, "Skip this metric")
    avm = [m1, m2, m3, m4, m5]
    lmetrics.append(Metric("Exploitability", avm))

    m1 = MetricValue("Official Fix", "OF", 0.87, "Complete vendor solution is available")
    m2 = MetricValue("Temporary Fix", "TF", 0.90, "Official but temporary fix available")
    m3 = MetricValue("Workaround", "W", 0.95, "Unofficial, non-vendor solution available")
    m4 = MetricValue("Unavailable", "U", 1.0, "No solution available or it is impossible to apply")
    m5 = MetricValue("Not Defined", "ND", 1.0, "Skip this metric")
    avm = [m1, m2, m3, m4, m5]
    lmetrics.append(Metric("Remediation Level", avm))

    m1 = MetricValue("Unconfirmed", "UC", 0.90, "Single unconfirmed source")
    m2 = MetricValue("Uncorroborated", "UR", 0.95, "Multiple non-official sources")
    m3 = MetricValue("Confirmed", "C", 1.0, "Acknowledged by the vendor or author")
    m4 = MetricValue("Not Defined", "ND", 1.0, "Skip this metric")
    avm = [m1, m2, m3, m4]
    lmetrics.append(Metric("Report Confidence", avm))

    m1 = MetricValue("None", "N", 0.0, "No potential for loss of life")
    m2 = MetricValue("Low", "L", 0.1, "Potential for slight physical or property damage")
    m3 = MetricValue("Low-Medium", "LM", 0.3, "Moderate physical or property damage")
    m4 = MetricValue("Medium-High", "MH", 0.4, "Significant physical or property damage or loss")
    m5 = MetricValue("High", "H", 0.5, "Catastrophic physical or property damage and loss")
    m6 = MetricValue("Not Defined", "ND", 0.9, "Skip this metric")
    avm = [m1, m2, m3, m4, m5, m6]
    lmetrics.append(Metric("Collateral Damage Potential", avm))

    m1 = MetricValue("None", "N", 0.0, "No target systems exist")
    m2 = MetricValue("Low", "L", 0.25, "Targets exist on a small scale inside the environment")
    m3 = MetricValue("Medium", "M", 0.75, "Targets exist on a medium scale")
    m4 = MetricValue("High", "H", 1.0, "Targets exist on a considerable scale")
    m5 = MetricValue("Not Defined", "ND", 1.0, "Skip this metric")
    avm = [m1, m2, m3, m4, m5]
    lmetrics.append(Metric("Target Distribution", avm))

    m1 = MetricValue("Low", "L", 0.5, "Limited adverse effect")
    m2 = MetricValue("Medium", "M", 1.0, "Serious adverse effect")
    m3 = MetricValue("High", "H", 1.51, "Catastrophic adverse effect")
    m4 = MetricValue("Not Defined", "ND", 1.0, "Skip this metric")
    avm = [m1, m2, m3, m4]
    lmetrics.append(Metric("Confidentiality Requirement", avm))
    lmetrics.append(Metric("Integrity Requirement", avm))
    lmetrics.append(Metric("Availability Requirement", avm))

    return CommonVulnerabilityScore(lmetrics)


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
