CVSS calculator for CVSS version 2.10
=====================================
The details of the Common Vulnerarbility Scoring System is described in [CVSS
Guide.](http://www.first.org/cvss/cvss-guide.html). 


Version
-------
VERSION = 1.20.1


What is new
-----------
Completed transformation to a Python package.


Howto
-----
Calculate the score by running the program and answering the questions:

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
To avoid installing 3rd party code directly we recommend the use of
[virtual environments](http://docs.python.org/3/library/venv.html#module-venv).
As of [Python version 3.3](http://docs.python.org/3/whatsnew/3.3.html)
virtual environments are part of the standard distribution.

Virtual environments simplify the creation of separate Python setups,
allows sharing the system-wide base install as well as enabling
private site-packages.  This means that using virtual environments we
can avoid the need to install packages in the system-wide
site-packages.  To get this up and running for the first time take the
following steps:

  * Make sure you have at least version 2.7 or 3.3 of Python installed.

  * Install pip in your virtual environment if it is no already there.
    For details [see.](https://pip.pypa.io/en/latest/installing.html)
    From version Python 3.4 it is already in place.

    * Using for example version 3.4 create your own virtual environment
      and activate it (the prompt changes after activation)

      $ pyvenv-3.4 ~/tmp/venv
      $ source venv/bin/activate
      (venv) $ deactive                     # does what is says...
      $ source venv/bin/activate

    * With version 2.7 first install virtualenv and then create your own
      virtual environment and activate it (the prompt changes after
      activation).  Make sure that setuptools and pip are updated.

      $ virtualenv-2.7 ~/venv/venv27
      $ . ~/venv/venv27/bin/activate
      (venv27) $ pip install -U setuptools
      (venv27) $ pip install -U pip

  * Finally download and install the required packages and do a quick test

    (venv) $ git clone https://github.com/FredrikHedman/CVSS.git
    (venv) $ cd CVSS
    (venv) $ pip install --editable .
    (venv) $ cvss -h                      # will list the help message

 Exit from the sub-shell environment by

    (venv) $ deactive          # does what is says...


Unit Tests, Case Tests and PEP8 compliance
------------------------------------------
The tests are combination of output driven tests and doctests.  All
tests are executed by

    (venv) $ make alltests

and individually by 

    (venv) $ make doctests
    (venv) $ make uctests

No output expected.  PEP8 compliance test can be checked by

    (venv) $ make pep8

Examples
--------
These are all based on CVSS examples using doctest.  No output is
expected.

    (venv) $ make examples


Developers
----------
Fredrik Hedman <fredrik.hedman@noruna.se>


