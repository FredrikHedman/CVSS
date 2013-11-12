#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.15
# LICENSE: MIT LICENSE
#
# Test for UC01
#
./cvss.py 2>&1 | diff test_uc01a.txt -
./cvss.py --help 2>&1 | diff test_uc01b.txt -
./cvss.py -h 2>&1 | diff test_uc01b.txt -
