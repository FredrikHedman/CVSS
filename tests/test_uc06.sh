#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#
# Regression test for possible bug
#
D=tests
IN=$D/test_uc06_in.txt
OUT1=$D/test_uc06_out.txt
OUT2=$D/test_uc06_verbose_out.txt
CVSS=cvss

${CVSS} -ia < $IN 2>&1 | diff - $OUT1 
${CVSS} -iav < $IN 2>&1 | diff - $OUT2
