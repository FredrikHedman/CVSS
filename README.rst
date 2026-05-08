CVSS calculator for CVSS version 2.10
=====================================
The details of the Common Vulnerability Scoring System is described in
`CVSS Guide <http://www.first.org/cvss/cvss-guide.html>`_.


Version
-------
VERSION = 2.0.0


What is new
-----------
Modernised packaging and tooling: migrated to ``uv`` + ``pyproject.toml``,
replaced ``flake8``/``pep8`` with ``ruff``, replaced shell-script test runners
with ``pytest``, dropped Python 2 support, and added full type annotations
verified by ``basedpyright``.


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


Development
-----------
Run the full test suite (pytest)::

      $ make test

Check and auto-fix code style (ruff)::

      $ make lint
      $ make format

Verify static types (basedpyright)::

      $ make typecheck

Run the example suite::

      $ make example

Remove build artefacts::

      $ make clean


Developers
----------
Fredrik Hedman <fredrik.hedman@noruna.se>


