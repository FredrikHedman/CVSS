help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  example        run example suite"
	@echo "  test           run test suite"
	@echo "  pep8           check for PEP8 compliance"
	@echo "  clean          clean out temporary files"

example:
	python3 examples/cvss_examples.py

test:
	./tests/run_all_tests.sh

pep8:
	flake8 --exclude=misc --ignore=D100,D101,D102,D103,D301,N803,N806 .

clean:
	/bin/rm -f *~ tests/*~ examples/*~ 
	/bin/rm -rf __pycache__ exmamples/__pycache__
