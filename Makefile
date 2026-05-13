help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  install    install/sync environment including dev dependencies"
	@echo "  build      build wheel and source distribution into dist/"
	@echo "  lock       regenerate uv.lock from pyproject.toml"
	@echo "  push       push commits and tags to origin (SSH passphrase required)"
	@echo "  fetch      fetch updates from origin (SSH passphrase required)"
	@echo "  test       run all tests (pytest)"
	@echo "  typecheck  run static type checking (basedpyright)"
	@echo "  lint       check for lint violations (ruff)"
	@echo "  format     auto-format source files (ruff)"
	@echo "  example    run example suite"
	@echo "  clean      remove temporary files and dist/"

install:
	uv sync --all-groups

build:
	uv build

lock:
	uv lock

push:
	git push origin master
	git push origin --tags

fetch:
	git fetch origin

test:
	uv run pytest

typecheck:
	uv run basedpyright

lint:
	uv run ruff check .

format:
	uv run ruff format .

example:
	uv run python -m cvss2.vulnerability examples/cvss_examples.py

clean:
	/bin/rm -f *~ */*~ *.pyc */*.pyc
	/bin/rm -rf __pycache__ examples/__pycache__
	/bin/rm -rf cvss.egg-info .pytest_cache dist
