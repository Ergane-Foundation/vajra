.DEFAULT_GOAL := help

PYTHON ?= python3
VENV   ?= venv
BIN    := $(VENV)/bin

ifeq ($(shell uname -s),Darwin)
START_SCRIPT := scripts/start_macos.sh
STOP_SCRIPT  := scripts/stop_macos.sh
else
START_SCRIPT := scripts/start.sh
STOP_SCRIPT  := scripts/stop.sh
endif

.PHONY: help install setup start stop status lint format test clean

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'

install: ## Install system packages (Suricata, Kafka); requires sudo
	sudo ./scripts/install.sh

setup: ## Create the virtualenv and install vajra in editable mode with dev tools
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

start: ## Start the pipeline (live mode, modifies host firewall); requires sudo
	sudo ./$(START_SCRIPT)

stop: ## Stop the pipeline; requires sudo
	sudo ./$(STOP_SCRIPT)

status: ## Show pipeline status
	$(PYTHON) scripts/status.py

lint: ## Lint Python sources
	$(BIN)/ruff check src tools tests

format: ## Format Python sources
	$(BIN)/ruff format src tools tests

test: ## Run the test suite
	$(BIN)/pytest

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .ruff_cache
