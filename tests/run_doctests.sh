#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.16
# LICENSE: MIT LICENSE
#
PYTHON=python3
$PYTHON metric_value.py
$PYTHON metric.py
$PYTHON cvss_210.py
$PYTHON vulnerability.py
$PYTHON test_vulnerability.py
$PYTHON examples/cvss_examples.py


