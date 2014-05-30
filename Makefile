help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  example        run example suite"
	@echo "  alltests       run all test suites"
	@echo "  doctests       run doctests"
	@echo "  uctests        run Use Case test suite"
	@echo "  pep8           check for PEP8 compliance"
	@echo "  clean          clean out temporary files"

example:
	python examples/cvss_examples.py

alltests:
	./tests/run_all_tests.sh

doctests:
	./tests/run_doctests.sh

uctests:
	./tests/test_uc.sh

pep8:
	flake8 --exclude=misc,examples --ignore=D102,D301,N803,N806,E701 .

clean:
	/bin/rm -f *~ */*~ *.pyc */*.pyc
	/bin/rm -rf __pycache__ examples/__pycache__
