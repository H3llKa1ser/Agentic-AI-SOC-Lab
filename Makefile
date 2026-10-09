install:
	pip install -e ".[dev]"

lint:
	ruff check . && ruff format --check .

test:
	pytest -q

check: lint test

demo:
	agentic-soc demo

fixtures:
	python scripts/generate_fixtures.py

eval:
	agentic-soc eval --repeat 3

.PHONY: install lint test check demo fixtures eval
