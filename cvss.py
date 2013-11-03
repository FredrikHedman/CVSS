#!/usr/bin/env python3
#
"""
Calculate CVSS metrics based on a list of Metrics.
"""
from metric import Metric
from cvss_base import CVSS
from cvss_210 import CommonVulnerabilityScore

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

def select_metric_value(m):
    m = Metric(*m)
    default_metric_value = m.index
    print(10*'+', m.name, m.short_name, 10*'+')
    while True:
        for v in m.values:
            print(v, v.description)
        idx = input('Select one [{0}]: '.format(default_metric_value))

        if not idx:
           idx = default_metric_value
        print('Selected metric value ###|', idx, '|###')

        try:
            m.index = idx
        except AssertionError:
            print('Not valid')
        else:
            return m.index

def base_display(cvs):
    H = ["BASE METRIC", "EVALUATION", "SCORE"]
    F = ["FORMULA", "BASE SCORE"]
    W0 = 30
    S1 = (W0*2 + len(H[2])) * '*'

    print(S1)
    print('{0:<{3}}{1:<{3}}{2}'.format(H[0], H[1], H[2], W0))
    print(S1)

    ml = cvs.base_metrics()
    for m in ml:
        print('{0:<{3}}{1:<{3}}{2:>5.2f}'.format(m.name,
                                           m.selected.metric,
                                           m.selected.number,
                                                 W0))
    print(S1)
    W2 = len(S1) - len(F[1])
    print('{0:<{2}}{1}'.format(F[0], F[1], W2))
    print(S1)

    print('{0:<{2}}{1:>5.2f}'.format('Impact =', round(cvs.impact,2), 2*W0))
    print('{0:<{2}}{1:>5.2f}'.format('Exploitability =', round(cvs.exploitability, 2), 2*W0))
    print('{0:<{2}}{1:>5.2f}'.format('Base Score =', cvs.base_score, 2*W0))
    print('Base Vulnerability Vector: {0}'.format(cvs.base_vulnerability_vector))

    print(S1)


def temporal_display(cvs):
    H = ["TEMPORAL METRIC", "EVALUATION", "SCORE"]
    F = ["FORMULA", "TEMPORAL SCORE"]
    W0 = 30
    S1 = (W0*2 + len(H[2])) * '*'

    print(S1)
    print('{0:<{3}}{1:<{3}}{2}'.format(H[0], H[1], H[2], W0))
    print(S1)

    ml = cvs.temporal_metrics()
    for m in ml:
        print('{0:<{3}}{1:<{3}}{2:>5.2f}'.format(m.name,
                                           m.selected.metric,
                                           m.selected.number,
                                           W0))

    print(S1)
    W2 = len(S1) - len(F[1])
    print('{0:<{2}}{1}'.format(F[0], F[1], W2))
    print(S1)

    print('{0:<{2}}{1:>5.2f}'.format('Temporal Score =', cvs.temporal_score, 2*W0))
    print('Temporal Vulnerability Vector: {0}'.format(cvs.temporal_vulnerability_vector))

    print(S1)


def environmental_display(cvs):
    H = ["ENIRONMENTAL METRIC", "EVALUATION", "SCORE"]
    F = ["FORMULA", "ENIRONMENTAL SCORE"]
    W0 = 30
    S1 = (W0*2 + len(H[2])) * '*'

    print(S1)
    print('{0:<{3}}{1:<{3}}{2}'.format(H[0], H[1], H[2], W0))
    print(S1)

    ml = cvs.environmental_metrics()
    for m in ml:
        print('{0:<{3}}{1:<{3}}{2:>5.2f}'.format(m.name,
                                                m.selected.metric,
                                                m.selected.number,
                                                W0))
    print(S1)
    W2 = len(S1) - len(F[1])
    print('{0:<{2}}{1}'.format(F[0], F[1], W2))
    print(S1)

    print('{0:<{2}}{1:>5.2f}'.format('Adjusted Impact =', cvs.adjusted_impact, 2*W0))
    print('{0:<{2}}{1:>5.2f}'.format('Adjusted Base =', cvs.adjusted_base_score, 2*W0))
    print('{0:<{2}}{1:>5.2f}'.format('Adjusted Temporal =', cvs.adjusted_temporal_score, 2*W0))
    print('{0:<{2}}{1:>5.2f}'.format('Enironmental Score =', cvs.environmental_score, 2*W0))
    print('Enironmental Vulnerability Vector: {0}'.format(cvs.environmental_vulnerability_vector))

    print(S1)

if __name__ == "__main__":
    selected = []

    L = base_metrics()
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)

    L = temporal_metrics()
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)

    L = environmental_metrics()
    for m in L:
        mm = select_metric_value(m)
        selected.append(mm)

    cvs = cvs_factory(CommonVulnerabilityScore, selected)

    base_display(cvs)
    temporal_display(cvs)
    environmental_display(cvs)

