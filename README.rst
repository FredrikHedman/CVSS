CVSS calculator for CVSS version 2.10
=====================================
The details of the Common Vulnerability Scoring System is described in
`CVSS Guide <http://www.first.org/cvss/cvss-guide.html>`_.


Version
-------
VERSION = 1.20.1


What is new
-----------
Completed transformation to a Python package.


How to
------
Calculate the score by running the program and answering the questions::

    $ cvss --help
    Calculate CVSS metrics based on a list of Metrics.

    Usage:
      cvss [-v] --interactive --all
      cvss [-v] --interactive [--temporal] --base [<vector>]
      cvss [-v] --interactive [--environmental] --temporal --base [<vector>]
      cvss [-v] --base <vector>
      cvss [-v] --vulnerability <vector>
      cvss (--help | --version)

    Options:
      -i --interactive          select metric values interactively
      -a --all                  ask for all metrics
      -b --base                 ask for base metrics
      -t --temporal             ask for temporal metrics
      -e --environmental        ask for environmental metrics
      <vector>                  base vulnerability vector
      --vulnerability <vector>  calculate score from vector

      -v --verbose              print verbose results
      -h --help                 show this help message and exit
      --version                 show version and exit


Installation
------------
Requires Python 3.10+ and `uv <https://docs.astral.sh/uv/>`_::

    $ git clone https://github.com/FredrikHedman/CVSS.git
    $ cd CVSS
    $ uv sync
    $ uv run cvss --help


Unit Tests, Use Case Tests and PEP8 compliance
----------------------------------------------
The tests are combination of output driven tests and doctests.  All
tests are executed by::

      $ make alltests

and individually by::

      $ make doctests
      $ make uctests

No output expected.  PEP8 compliance test can be checked by::

      $ make pep8

Examples
--------
These are all based on CVSS examples using doctest.  No output is
expected::

      $ make examples


Developers
----------
Fredrik Hedman <fredrik.hedman@noruna.se>


