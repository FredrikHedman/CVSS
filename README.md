# What

CVSS calculator for CVSS version 2.10

# Version

1.14

# Developers

Fredrik Hedman

# Howto

Calculate the score by running the program and answering the questions:

    $ python3.3 cvss.py --help
      Calculate CVSS metrics based on a list of Metrics.

      Usage:
        cvss.py (-i | --interactive) [-v | --verbose] [-a | --all]
        cvss.py (-i | --interactive) [-v | --verbose] [-b | --base [ -t | --temporal [-e | --environmental] ] ]
        cvss.py [-v | --verbose] --vulnerability <vector>
        cvss.py (-h | --help | --version)

      Options:
        -i --interactive          select metric values interactively
        -a --all                  ask for all metrics
        -b --base                 ask for base metrics
        -t --temporal             ask for temporal metrics
        -e --environmental        ask for environmental metrics
        --vulnerability <vector>  calculate score from vector

        -v --verbose              print verbose results
        -h --help                 show this help message and exit
        --version                 show version and exit

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
