#! /usr/bin/env python3
#
"""Calculate CVSS (version 2) score.

Formulas are extracted from http://www.first.org/cvss/cvss-guide.html
and tests are based on the examples shown in this document.
"""
import argparse
def cvss(parser):
    args = parser.parse_args()
    return args

def calculate_cvss_score(ibias):
    return (0,0)

def calculate_risk(tscore):
    return None

def calculate_vector(ibias):
    return "foo/bar"

def present_results(score, risk_factor, basescore_vector):
    print(score, risk_factor, basescore_vector)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Caculate CVSS v2 score.')
    impact_bias = cvss(parser)
    score = calculate_cvss_score(impact_bias)
    risk_factor = calculate_risk(score[1])
    basescore_vector = calculate_vector(impact_bias)

    present_results(score, risk_factor, basescore_vector)
