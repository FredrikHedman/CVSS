#!/bin/bash -v
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.14
# LICENSE: MIT LICENSE
#
# Test for UC02
#
./cvss.py -ib < test_uc02_in.txt 2>&1 | diff test_uc02_out.txt -
./cvss.py -ivb < test_uc02_in.txt 2>&1 | diff test_uc02_verbose_out.txt -
