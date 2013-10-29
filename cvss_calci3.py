#! /usr/bin/env python3
#
"""Calculate CVSS (version 2) score.

Formulas are extracted from http://www.first.org/cvss/cvss-guide.html
and tests are based on the examples shown in this document.
"""
import argparse

parser = argparse.ArgumentParser(description='Caculate CVSS v2 score.')
args = parser.parse_args()

