.PHONY: help install install-dev test test-unit test-integration coverage clean format lint type-check run-server run-client

help:
	@echo "SecureChat Development Commands"
	@echo "==============================="
	@echo "install          Install production dependencies"
	@echo "install-dev      Install development dependencies"
	@echo "test             Run all tests"
	@echo "test-unit        Run unit tests only"
	@echo "coverage         Run tests with coverage report"
	@echo "format           Format code with black"
	@echo "lint             Run linting checks"
	@echo "type-check       Run mypy type checking"
	@echo "clean            Remove generated files"
	@echo "run-server       Start relay server"
	@echo "run-client       Start CLI client"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest

test-unit:
	pytest tests/unit -v

test-integration:
	pytest tests/integration -v

coverage:
	pytest --cov=src --cov-report=html --cov-report=term

format:
	black src/ tests/

lint:
	black --check src/ tests/

type-check:
	mypy src/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov/ dist/ build/

run-server:
	python -m src.server.main

run-client:
	python -m src.client.cli
