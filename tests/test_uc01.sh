#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20
# LICENSE: MIT LICENSE
#
# Test for UC01
#
CVSS=cvss
$(CVSS) 2>&1 | diff tests/test_uc01a.txt -
$(CVSS) --help 2>&1 | diff tests/test_uc01b.txt -
$(CVSS) -h 2>&1 | diff tests/test_uc01b.txt -
