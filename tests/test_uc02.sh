#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.15
# LICENSE: MIT LICENSE
#
# Test for UC02
#
./cvss.py -ib < tests/test_uc02_in.txt 2>&1 | diff tests/test_uc02_out.txt -
./cvss.py -ivb < tests/test_uc02_in.txt 2>&1 | diff tests/test_uc02_verbose_out.txt -
