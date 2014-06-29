FLAKEFLAGS  =--max-complexity 11 --show-pep8 --exclude=misc
FLAKEFLAGS += --ignore=D100,D101,D102,D103,D301,N803

help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  example        run example suite"
	@echo "  alltests       run all test suites"
	@echo "  doctests       run doctests"
	@echo "  uctests        run Use Case test suite"
	@echo "  pep8           check for PEP8 compliance"
	@echo "  clean          clean out temporary files"

example:
	python -m vulnerability examples/cvss_examples.py

alltests:
	./tests/run_all_tests.sh

doctests:
	./tests/run_doctests.sh

uctests:
	./tests/test_uc.sh

pep8:
	flake8 $(FLAKEFLAGS) .

clean:
	/bin/rm -f *~ */*~ *.pyc */*.pyc
	/bin/rm -rf __pycache__ examples/__pycache__
