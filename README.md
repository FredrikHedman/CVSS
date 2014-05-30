# What

CVSS calculator for CVSS version 2.10

# Version

VERSION = 1.20

# Developers

Fredrik Hedman

# Installation

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

  * Make sure you have at least version 3.3 of Python installed.

  * Using for example version 3.4 create your own virtual environment
    and activate it

        $ pyvenv-3.4 ~/tmp/venv
        $ source venv/bin/activate
        (venv) $ deactive          # does what is says...
        $ source venv/bin/activate

  * Install pip in your virtual environment if it is no already there.

  * Finally download and install the required packages and do a quick test

        (venv) $ git clone https://github.com/FredrikHedman/CVSS.git
        (venv) $ cd CVSS
        (venv) $ pip install -r requirements.txt
        (venv) $ ./cvss.py -h                     # will list the help message

Note that this virtual environment does not have to be prepped every
time there is a new version.  Only when and if the requirements.txt
changes. Exit from the sub-shell environment by

        (venv) $ deactive          # does what is says...


# Howto

Calculate the score by running the program and answering the questions:

    $ python cvss.py --help
    Calculate CVSS metrics based on a list of Metrics.

    Usage:
      cvss.py [-v] --interactive --all
      cvss.py [-v] --interactive [--temporal] --base [<vector>]
      cvss.py [-v] --interactive [--environmental] --temporal --base [<vector>]
      cvss.py [-v] --base <vector>
      cvss.py [-v] --vulnerability <vector>
      cvss.py (--help | --version)

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

# Unit Tests and Use Case Tests

The tests are combination of output driven tests and doctests.  All
tests are executed by

     $ make alltests

and individually by 

    $ make doctests
    $ make uctests

No output expected.  PEP8 compliance is checked by

     $ make pep8

# Examples

These are all based on CVSS examples using doctest.  No output is
expected.

    $ make examples

