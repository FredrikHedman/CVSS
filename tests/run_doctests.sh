#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.1
# LICENSE: MIT LICENSE
#
PYTHON=python3
$PYTHON metric_value.py
$PYTHON metric.py
$PYTHON cvss_210.py
$PYTHON vulnerability.py
$PYTHON test_vulnerability.py
$PYTHON examples/cvss_examples.py


