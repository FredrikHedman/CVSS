# What

CVSS calculator for CVSS version 2.10

# Version

1.13.1

# Developers

Fredrik Hedman

# Howto

Calculate the score by running the program and answering the questions:

    $ python3.3 cvss.py
    Usage:
      cvss.py (-i | --interactive) [-v | --verbose]
      cvss.py (-h | --help | --version)

# Unit Tests 

The tests are all doctests.  No output is expected.

     $ python3 metric.py
     $ python3 metric_value.py

* Examples

These are all based on CVSS examples using doctest.  No output is
expected.

    $ python3 cvss_examples.py

You can also run all the examples with

    $ ./run_tests.sh

No output expected.
