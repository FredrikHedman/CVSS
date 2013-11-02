#!/usr/bin/env python3
#
"""
Calculate CVSS metrics based on a list of Metrics.
"""
from metric import Metric

def base_metrics():
    BASE_METRICS = [
        ["Access Vector", "AV",
         [("Local", "L", 0.395, "Local access"),
          ("Adjecent Network", "A", 0.646, "Adjacent network access"),
          ("Network", "N", 1.0, "Network access") ]],
        ["Access Complexity", "AC",
         [("High", "H", 0.35, "Specialized access conditions exist"),
          ("Medium", "M", 0.61, "The access conditions are somewhat specialized"),
          ("Low", "L", 0.71, "No specialized access exist") ]],
        ["Authentication", "Au",
         [("Multiple", "M", 0.45, "Authenticate two or more times"),
          ("Single", "S", 0.56, "Logged into the system"),
          ("None", "N", 0.704, "Authentication not required") ]],
        ["Confidentiality Impact", "C",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275, "Considerable disclosure"),
          ("Complete", "C", 0.660, "Total inforamtion disclosure") ]],
        ["Integrity Impact", "I",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275, "Possible to modify some system files or information"),
          ("Complete", "C", 0.660, "Total compromise of system integrity") ]],
        ["Availability Impact", "A",
         [("None", "N", 0.0, "No impact"),
          ("Partial", "P", 0.275, "Reduced performance or interruptions in resource availability"),
          ("Complete", "C", 0.660, "Total shutdown of the affected resource") ]],
    ]
    return BASE_METRICS


def temporal_metrics():
    TEMPORAL_METRICS = [
    ["Exploitability", "E",
     [("Unproven", "U", 0.85, "No exploit code is available"),
      ("Proof-of-Concept", "POC", 0.9, "Proof-of-concept exploit code exists"),
      ("Functional", "F", 0.95, "Functional exploit code is available"),
      ("High", "H", 1.0, "Exploitable by functional mobile autonomous code"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Remediation Level", "RL",
     [("Official Fix", "OF", 0.87, "Complete vendor solution is available"),
      ("Temporary Fix", "TF", 0.90, "Official but temporary fix available"),
      ("Workaround", "W", 0.95, "Unofficial, non-vendor solution available"),
      ("Unavailable", "U", 1.0, "No solution available or it is impossible to apply"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Report Confidence", "RC",
     [("Unconfirmed", "UC", 0.90, "Single unconfirmed source"),
      ("Uncorroborated", "UR", 0.95, "Multiple non-official sources"),
      ("Confirmed", "C", 1.0, "Acknowledged by the vendor or author"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ]
    return TEMPORAL_METRICS

def environmental_metrics():
    ENVIRONMENTAL_METRICS = [
    ["Collateral Damage Potential", "CDP",
     [("None", "N", 0.0, "No potential for loss of life"),
      ("Low", "L", 0.1, "Potential for slight physical or property damage"),
      ("Low-Medium", "LM", 0.3, "Moderate physical or property damage"),
      ("Medium-High", "MH", 0.4, "Significant physical or property damage or loss"),
      ("High", "H", 0.5, "Catastrophic physical or property damage and loss"),
      ("Not Defined", "ND", 0.9, "Skip this metric") ]],
    ["Target Distribution", "TD",
     [("None", "N", 0.0, "No target systems exist"),
      ("Low", "L", 0.25, "Targets exist on a small scale inside the environment"),
      ("Medium", "M", 0.75, "Targets exist on a medium scale"),
      ("High", "H", 1.0, "Targets exist on a considerable scale"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Confidentiality Requirement", "CR",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Integrity Requirement", "IR",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ["Availability Requirement", "AR",
     [("Low", "L", 0.5, "Limited adverse effect"),
      ("Medium", "M", 1.0, "Serious adverse effect"),
      ("High", "H", 1.51, "Catastrophic adverse effect"),
      ("Not Defined", "ND", 1.0, "Skip this metric") ]],
    ]
    return ENVIRONMENTAL_METRICS

def add_padding(to_length, selected):
    if selected == None:
        selected =  []
    padding = to_length - len(selected)
    if padding:
        selected.extend(padding * [None])
    return selected

def prepare_metrics(L, selected):
    lmetrics = []
    for ii, mm in enumerate(L):
        lmetrics.append(Metric(*mm, index = selected[ii]))
    return lmetrics

def cvs_factory(cls, selected = None):
    L = base_metrics()
    L.extend(temporal_metrics())
    L.extend(environmental_metrics())
    selected = add_padding(len(L), selected)
    lmetrics = prepare_metrics(L, selected)
    return cls(lmetrics)


class cvssv210:
    def __init__(self, metrics_seq):
        self.__metrics = {}
        for m in metrics_seq:
            self.__metrics[m.short_name] = m
        assert len(self.__metrics) == len(metrics_seq), 'Metric short name collision'

    def __getitem__(self, idx):
        return self.__metrics[idx]

    @property
    def _base_vector(self):
        vv = ['AV', 'AC', 'Au', 'C', 'I', 'A']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)

    @property
    def _temporal_vector(self):
        vv = ['E', 'RL', 'RC']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)

    @property
    def _environmental_vector(self):
        vv = ['CDP', 'TD', 'CR', 'IR', 'AR']
        vstr = []
        for v in vv:
            vstr.append("{0}:{1}".format(v, str(self[v])))
        return '/'.join(vstr)

    @property
    def exploitability(self):
        res = 20.0
        res *= float(self['AV'])
        res *= float(self['AC'])
        res *= float(self['Au'])
        return res

    @property
    def impact(self):
        ConfImpact = float(self['C'])
        IntegImpact = float(self['I'])
        AvailImpact = float(self['A'])
        return self._impact_fcn(ConfImpact, IntegImpact, AvailImpact)

    @property
    def adjusted_impact(self):
        ConfImpact = float(self['C']) * float(self['CR'])
        IntegImpact = float(self['I']) * float(self['IR'])
        AvailImpact = float(self['A']) * float(self['AR'])
        result = self._impact_fcn(ConfImpact, IntegImpact, AvailImpact)
        return min(10.0, result)

    def _impact_fcn(self, conf_impact, integ_impact, avail_impact):
        result = 1 - (1-conf_impact)*(1-integ_impact)*(1-avail_impact)
        result *= 10.41
        return result

    def _fcn(self, impact):
        val = 1.176
        if impact == 0:
            val = 0.0
        return val

    def _base_fcn(self, impact):
        score = (0.6*impact + 0.4*self.exploitability - 1.5)
        score *= self._fcn(impact)
        return score

    def _temporal_fcn(self, score):
        score *= float(self['E'])
        score *= float(self['RL'])
        score *= float(self['RC'])
        return score

    def _environmental_fcn(self, adjusted_temporal_score):
        score = adjusted_temporal_score
        score += (10.0 - adjusted_temporal_score)*float(self['CDP'])
        score *= float(self['TD'])
        return score


class CommonVulnerabilityScore(cvssv210):
    def __init__(self, metrics_seq):
        super().__init__(metrics_seq)

    @property
    def base_score(self):
        return round(self._base_fcn(self.impact), ndigits=1)

    @property
    def adjusted_base_score(self):
        return round(self._base_fcn(self.adjusted_impact), ndigits=1)

    @property
    def temporal_score(self):
        return round(self._temporal_fcn(self.base_score), ndigits=1)

    @property
    def adjusted_temporal_score(self):
        return round(self._temporal_fcn(self.adjusted_base_score), ndigits=1)

    @property
    def environmental_score(self):
        return round(self._environmental_fcn(self.adjusted_temporal_score), ndigits=1)

    @property
    def base_vulnerability_vector(self):
        return self._base_vector

    @property
    def temporal_vulnerability_vector(self):
        return self._temporal_vector

    @property
    def environmental_vulnerability_vector(self):
        return self._environmental_vector

if __name__ == "__main__":
    import doctest
    doctest.testmod()
