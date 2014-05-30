#!/bin/bash
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20
# LICENSE: MIT LICENSE
#
# Tests for UC04 (for now, same as for UC03)
#
PGM=./cvss.py
# Empty end
$PGM -ib 'a:b/c:d/' 2>&1 | diff tests/test_uc03_empty_end_out.txt -
# Bad key
$PGM -ib 'a:b/c:d/' 2>&1 | diff tests/test_uc03_bad_key_out.txt -
# Incorrect value
s=AV:A/AC:M/Au:M/C:P/I:P/A:X
$PGM -ib $s 2>&1 | diff tests/test_uc03_bad_value_out.txt -
# Not enough keys
s=AV:A/AC:M/Au:M/C:P/I:P
$PGM -ib $s 2>&1 | diff tests/test_uc03_not_enough_keys_out.txt -
# Duplicate keys
s=AV:A/AV:A/Au:S/C:C/I:P/A:C
$PGM --base $s  2>&1 | diff tests/test_uc03_base_dup_out.txt -
# Inccorect order
s=AV:A/A:P/AC:M/Au:M/C:P/I:P
$PGM -ib $s 2>&1 | diff tests/test_uc03_bad_order_out.txt -
# Incorrect params
for pp in -it -ie -ibe -ite; do
   $PGM $pp   2>&1 | diff tests/test_uc03_bad_params_out.txt -
done
$PGM -ib 'abc' -e   2>&1 | diff tests/test_uc03_bad_params_out.txt -
# Base only
s=AV:A/AC:M/Au:S/C:C/I:P/A:C
$PGM --base $s  2>&1 | diff tests/test_uc03_base_out.txt -
# Adding Temporal
s=AV:A/AC:M/Au:S/C:C/I:P/A:C
f=tests/test_uc03_temporal
$PGM -it --base $s < ${f}_in.txt 2>&1 | diff ${f}_out.txt -
# Adding Environmental
s=AV:A/AC:M/Au:S/C:C/I:P/A:C
f=tests/test_uc03_environmental
$PGM -ite --base $s < ${f}_in.txt 2>&1 | diff ${f}_out.txt -
