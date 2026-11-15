.PHONY: help install install-dev test test-cov lint format typecheck check clean build publish update-data data-info scan scan-pr

PYTHON ?= python3

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Setup ──────────────────────────────────────────────
install: ## Install ExposureGate
	$(PYTHON) -m pip install .

install-dev: ## Install with dev dependencies
	$(PYTHON) -m pip install -e ".[dev]"

# ─── Testing ────────────────────────────────────────────
test: ## Run tests
	$(PYTHON) -m pytest -q

test-cov: ## Run tests with coverage report (fails under 90%)
	$(PYTHON) -m pytest -q --cov=exposuregate --cov-report=term-missing --cov-report=html

# ─── Code Quality ──────────────────────────────────────
lint: ## Run linter (ruff)
	$(PYTHON) -m ruff check .

format: ## Apply ruff's automatic lint fixes (import order, upgrades)
	$(PYTHON) -m ruff check --fix .

typecheck: ## Run type checker (mypy, strict)
	$(PYTHON) -m mypy src

check: lint typecheck test ## Run all checks (lint + typecheck + test)

# ─── Build & Publish ───────────────────────────────────
clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean ## Build distribution packages
	$(PYTHON) -m build

publish: build ## Publish to PyPI by hand (CI normally does this via Trusted Publishing; needs TWINE_PASSWORD)
	$(PYTHON) -m twine check dist/*
	$(PYTHON) -m twine upload dist/*

# ─── ExposureGate Usage ────────────────────────────────
update-data: ## Download the OEBC catalog and the OSV PyPI and npm exports
	$(PYTHON) -m exposuregate update-data

data-info: ## Show the local data snapshot
	$(PYTHON) -m exposuregate data-info

scan: ## Run ExposureGate on the staged lockfiles (pre-commit mode)
	$(PYTHON) -m exposuregate scan --mode pre-commit

scan-pr: ## Run ExposureGate in PR mode against main
	$(PYTHON) -m exposuregate scan --mode pr --target-branch main
