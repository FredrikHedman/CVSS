#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20
# LICENSE: MIT LICENSE
#
PYTHON=python
$PYTHON metric_value.py
$PYTHON -m metric_value examples/test_metric_value.py
$PYTHON metric.py
$PYTHON cvss_210.py
$PYTHON vulnerability.py
$PYTHON -m vulnerability examples/test_vulnerability.py
$PYTHON -m metric_value examples/cvss_examples.py


