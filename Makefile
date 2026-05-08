help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  test       run all tests (pytest)"
	@echo "  typecheck  run static type checking (basedpyright)"
	@echo "  lint       check for lint violations (ruff)"
	@echo "  format     auto-format source files (ruff)"
	@echo "  example    run example suite"
	@echo "  clean      clean out temporary files"

test:
	uv run pytest

typecheck:
	uv run basedpyright

lint:
	uv run ruff check .

format:
	uv run ruff format .

example:
	uv run python -m cvss.vulnerability examples/cvss_examples.py

clean:
	/bin/rm -f *~ */*~ *.pyc */*.pyc
	/bin/rm -rf __pycache__ examples/__pycache__
	/bin/rm -rf cvss.egg-info .pytest_cache
