#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
PYTHON=python
$PYTHON -m cvss.metric_value examples/test_metric_value.py
$PYTHON -m cvss.metric examples/test_metric.py
$PYTHON -m cvss.vulnerability examples/test_vulnerability.py
$PYTHON -m cvss.metric_value examples/cvss_examples.py


