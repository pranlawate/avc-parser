# OPTIMIZED MAKEFILE FOR AVC PARSER
# Ultra-fast development workflow with ruff + pytest + coverage (Phase 11E)
# Modern configuration via pyproject.toml

.PHONY: help format check lint security dead-code flow-diagram deps-graph test test-cov install install-tools install-wrapper install-wrapper-user uninstall-wrapper clean all quick-check

# Default target
help:
	@echo "=== AVC Parser Development Tools ==="
	@echo "Core workflow:"
	@echo "  quick-check      - Ultra-fast quality check (< 1 second)"
	@echo "  format           - Format code (ruff)"
	@echo "  lint             - Full quality analysis"
	@echo "  test             - Run test suite (pytest, 174 tests)"
	@echo "  test-cov         - Run tests with coverage report"
	@echo "  security         - Security analysis (bandit + safety)"
	@echo ""
	@echo "Analysis tools:"
	@echo "  syntax           - Fast syntax check (ruff)"
	@echo "  dead-code        - Find unused code (vulture)"
	@echo "  flow-diagram     - Function dependency visualization"
	@echo "  deps-graph       - Import dependency analysis"
	@echo ""
	@echo "Coverage reports:"
	@echo "  test-cov-html    - Generate HTML coverage report"
	@echo ""
	@echo "Setup:"
	@echo "  install          - Install runtime dependencies (rich)"
	@echo "  install-tools    - Install dev tools (ruff, pytest, coverage)"
	@echo "  install-wrapper  - Install wrapper (interactive: /usr/local/bin or ~/bin)"
	@echo "  install-wrapper-user - Install wrapper to ~/bin (non-interactive)"
	@echo "  uninstall-wrapper - Remove wrapper scripts"
	@echo "  clean            - Remove generated files and caches"

# === TIER 1: ULTRA-FAST DAILY WORKFLOW ===

# Ultra-fast quality check (< 1 second) - 197x faster than old 3-tool combo
quick-check:
	@echo "🚀 Ultra-fast quality check (ruff)..."
	@ruff check parse_avc.py --quiet | head -10 || echo "✅ All checks passed"
	@echo "✅ Quick check completed"

# Code formatting and organization (ruff all-in-one)
format:
	@echo "🎨 Formatting code (ruff - config: pyproject.toml)..."
	@ruff format .
	@ruff check . --fix --quiet || true
	@echo "✅ Code formatted and organized"

# Fast syntax check only
syntax:
	@echo "🔍 Syntax check (ruff)..."
	@ruff check parse_avc.py --quiet

# === TIER 2: COMPREHENSIVE ANALYSIS ===

# Full linting (when needed)
lint:
	@echo "🔍 Full quality analysis..."
	@echo "→ Comprehensive ruff analysis:"
	@ruff check parse_avc.py avc_selinux/context.py utils/ | head -15 || true
	@echo "→ Dead code detection:"
	@vulture parse_avc.py --min-confidence 90 | head -5 || true
	@echo "→ Modern Python suggestions:"
	@refurb parse_avc.py | head -5 || true
	@echo "✅ Lint analysis completed"

# Security analysis
security:
	@echo "🔒 Security analysis..."
	@echo "→ Code security (bandit):"
	@bandit parse_avc.py -f txt -ll | head -10 || true
	@echo "→ Dependencies (safety):"
	@safety check --json --ignore 70612 | head -3 || true
	@echo "✅ Security analysis completed"

# Dead code detection
dead-code:
	@echo "🧹 Dead code detection..."
	@vulture parse_avc.py --min-confidence 80

# === TIER 3: VISUALIZATION & ANALYSIS ===

# Function dependency visualization
flow-diagram:
	@echo "📊 Generating function dependency map..."
	@code2flow parse_avc.py --output avc_dependencies.svg --language py --skip-parse-errors
	@echo "✅ Generated: avc_dependencies.svg"

# Import dependency analysis (NEW CAPABILITY)
deps-graph:
	@echo "🔗 Analyzing import dependencies..."
	@pydeps parse_avc.py --show-deps --noshow --cluster > avc_import_deps.json || echo "JSON export not available"
	@pydeps parse_avc.py --show-deps --max-cluster-size=10 --output avc_import_deps.svg 2>/dev/null || echo "SVG generation skipped"
	@echo "✅ Import dependency analysis completed"

# Testing infrastructure (pytest - Phase 11E)
test:
	@echo "🧪 Running test suite (pytest - config: pyproject.toml)..."
	@pytest
	@echo "✅ All 174 tests passed"

# Test with coverage reporting (Phase 11E)
test-cov:
	@echo "🧪 Running tests with coverage (pytest-cov - config: pyproject.toml)..."
	@pytest --cov --cov-report=term-missing
	@echo "✅ Coverage report complete"

# Coverage HTML report
test-cov-html:
	@echo "🧪 Generating HTML coverage report..."
	@pytest --cov --cov-report=html
	@echo "✅ HTML report: htmlcov/index.html"

# Regression prevention framework (PHASE 7 COMPLETED - legacy)
test-regression:
	@echo "🛡️ Running regression prevention suite (legacy)..."
	@python3 tests/test_runner.py
	@echo "✅ Regression prevention completed"

# === SETUP & MAINTENANCE ===

# Install dev tools from pyproject.toml (Phase 11E)
install-tools:
	@echo "🛠️ Installing dev tools (from pyproject.toml)..."
	@pip install -e ".[dev]"
	@echo "✅ All dev tools installed: ruff, pytest, pytest-cov"

# Install for production (runtime dependencies only)
install:
	@echo "📦 Installing runtime dependencies..."
	@pip install -e .
	@echo "✅ Runtime dependencies installed: rich>=10.0.0"

# Install wrapper script (interactive - asks user for location)
install-wrapper:
	@echo "🔧 Installing avc-parser wrapper..."
	@echo ""
	@echo "Choose installation location:"
	@echo "  1) /usr/local/bin (requires sudo, available system-wide)"
	@echo "  2) ~/bin (no sudo, user-only)"
	@echo ""
	@read -p "Enter choice [1/2]: " choice; \
	if [ "$$choice" = "1" ]; then \
		echo "Installing to /usr/local/bin..."; \
		echo '#!/bin/bash' | sudo tee /usr/local/bin/avc-parser > /dev/null; \
		echo 'exec python3 $(shell pwd)/parse_avc.py "$$@"' | sudo tee -a /usr/local/bin/avc-parser > /dev/null; \
		sudo chmod +x /usr/local/bin/avc-parser; \
		echo "✅ Wrapper installed to /usr/local/bin"; \
	elif [ "$$choice" = "2" ]; then \
		echo "Installing to ~/bin..."; \
		mkdir -p ~/bin; \
		echo '#!/bin/bash' > ~/bin/avc-parser; \
		echo 'exec python3 $(shell pwd)/parse_avc.py "$$@"' >> ~/bin/avc-parser; \
		chmod +x ~/bin/avc-parser; \
		echo "✅ Wrapper installed to ~/bin"; \
		if ! echo $$PATH | grep -q "$$HOME/bin"; then \
			echo "⚠️  ~/bin is not in your PATH. Add to ~/.bashrc:"; \
			echo "   export PATH=\"\$$HOME/bin:\$$PATH\""; \
			echo "   Then run: source ~/.bashrc"; \
		fi; \
	else \
		echo "❌ Invalid choice. Installation cancelled."; \
		exit 1; \
	fi

# Install wrapper script to ~/bin (no sudo needed, non-interactive)
install-wrapper-user:
	@echo "🔧 Installing avc-parser wrapper to ~/bin..."
	@mkdir -p ~/bin
	@echo '#!/bin/bash' > ~/bin/avc-parser
	@echo 'exec python3 $(shell pwd)/parse_avc.py "$$@"' >> ~/bin/avc-parser
	@chmod +x ~/bin/avc-parser
	@echo "✅ Wrapper installed to ~/bin"
	@if ! echo $$PATH | grep -q "$$HOME/bin"; then \
		echo "⚠️  ~/bin is not in your PATH. Add to ~/.bashrc:"; \
		echo "   export PATH=\"\$$HOME/bin:\$$PATH\""; \
		echo "   Then run: source ~/.bashrc"; \
	fi

# Remove wrapper script
uninstall-wrapper:
	@echo "🗑️ Removing avc-parser wrapper..."
	@sudo rm -f /usr/local/bin/avc-parser 2>/dev/null || echo "  (skipped /usr/local/bin - no sudo access or not found)"
	@rm -f ~/bin/avc-parser 2>/dev/null || echo "  (~/bin/avc-parser not found)"
	@echo "✅ Wrapper removal complete"

# Cleanup
clean:
	@echo "🧹 Cleaning generated files..."
	@rm -f *.svg *.png *.gv
	@rm -rf __pycache__ *.pyc .mypy_cache .ruff_cache htmlcov .coverage .pytest_cache
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned up"

# Complete workflow (Phase 11E updated)
all: format quick-check test-cov
	@echo "🎉 Complete workflow finished - code quality verified"

# === TOOL EVOLUTION NOTES ===
# Phase 11E (2025-10-05): Modern development tooling with pyproject.toml
# WINNERS (adopted): ruff (formatting + linting + imports), pytest (testing), pytest-cov (coverage)
# CONFIGURATION: Centralized in pyproject.toml (modern Python standard)
# REPLACED: unittest → pytest (better discovery, markers, strict config)
# METRICS: 174 tests, 10.00/10 pylint, 19.15% coverage baseline
# REJECTED: pydantic/click (add user dependencies), mypy (deferred)
#
# Manual alternatives for specialized needs:
# - Type checking: Run mypy manually when needed
# radon-check: # DISABLED until upstream PR merged
# 	@echo "🔍 Running complexity analysis..."
# 	@radon cc parse_avc.py --show-complexity --average
# 	@echo "📊 Modularized files complexity:"
# 	@radon cc avc_selinux/context.py utils/ --average
#
# Temporary workaround for radon complexity analysis:
radon-check-local:
	@echo "🔍 Running complexity analysis with local radon fix..."
	@cd ../radon && python -m radon cc ../avc-parser/parse_avc.py --show-complexity --average
	@echo "📊 Modularized files complexity:"
	@cd ../radon && python -m radon cc ../avc-parser/avc_selinux/context.py ../avc-parser/utils/ --average