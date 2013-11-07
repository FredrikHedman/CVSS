# What

CVSS calculator for CVSS version 2.10

# Version

1.14

# Developers

Fredrik Hedman

# Installation

    $ git clone https://github.com/FredrikHedman/CVSS.git
    $ sudo pip3 install -r requirements.txt

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

# Installation

To avoid installing 3rd party code directly we use
[virtual environments](http://docs.python.org/3/library/venv.html#module-venv)
that is now included in python as of
[version 3.3](http://docs.python.org/3/whatsnew/3.3.html).  To get
this up and running for the first time take the following steps:

  * Create your own virtual environment and activate it

        $ pyvenv-3.3 ~/tmp/venv
        $ source venv/bin/activate
        (venv) $ deactive          # does what is says...
        $ source venv/bin/activate

  * Install pip in your virtual environment

        (venv) $ cd ~/tmp/venv
        (venv) $ wget https://bitbucket.org/pypa/setuptools/raw/bootstrap/ez_setup.py
        (venv) $ wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
        (venv) $ python ez_setup.py               # install setuptools for use by pip
        (venv) $ python get-pip.py                # install pip
        (venv) $ pip install --upgrade setuptools # just to be sure

  * Verify that pip and ilk are installed in your venv.  Yous should
    see python, pip and easy_install listed with

        (venv) ls -l ~/tmp/venv/bin/{p,e}*

  * Finally install the required packages and do a quick test

        (venv) $ cd CVSSScore
        (venv) $ pip install -r requirements.txt
        (venv) $ ./cvss.py -h                     # will list the help message

Note that this virtual environment does not have to be prepped every
time there is a new version.  Only when and if the requirements.txt
changes.

# Unit Tests 

The tests are all doctests.  No output is expected.

     $ python3 metric.py
     $ python3 metric_value.py

# Examples

These are all based on CVSS examples using doctest.  No output is
expected.

    $ python3 cvss_examples.py

You can also run all the examples with

    $ ./run_tests.sh

No output expected.
