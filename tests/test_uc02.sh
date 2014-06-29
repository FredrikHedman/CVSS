#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20
# LICENSE: MIT LICENSE
#
# Test for UC02
#
CVSS=cvss
$(CVSS) -ib < tests/test_uc02_in.txt 2>&1 | diff tests/test_uc02_out.txt -
$(CVSS) -ivb < tests/test_uc02_in.txt 2>&1 | diff tests/test_uc02_verbose_out.txt -
