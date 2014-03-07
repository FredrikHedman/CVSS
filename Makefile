help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  example        run example suite"
	@echo "  test            run test suite"
	@echo "  clean           clean out temporary files"

example:
	python3 examples/cvss_examples.py

test:
	./tests/run_all_tests.sh

clean:
	/bin/rm -f *~ tests/*~ examples/*~ 
	/bin/rm -rf __pycache__ exmamples/__pycache__
