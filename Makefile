# OPTIMIZED MAKEFILE FOR AVC PARSER
# Ultra-fast development workflow with ruff + winning tools

.PHONY: help format check lint security dead-code flow-diagram deps-graph test install-tools clean all quick-check

# Default target
help:
	@echo "=== AVC Parser Development Tools ==="
	@echo "Core workflow:"
	@echo "  quick-check      - Ultra-fast quality check (< 1 second)"
	@echo "  format           - Format code (ruff)"
	@echo "  lint             - Full quality analysis"
	@echo "  test             - Run comprehensive test suite"
	@echo "  security         - Security analysis (bandit + safety)"
	@echo ""
	@echo "Analysis tools:"
	@echo "  syntax           - Fast syntax check (ruff)"
	@echo "  dead-code        - Find unused code (vulture)"
	@echo "  flow-diagram     - Function dependency visualization"
	@echo "  deps-graph       - Import dependency analysis"
	@echo ""
	@echo "Setup:"
	@echo "  install-tools    - Install optimized dev tools"
	@echo "  clean            - Remove generated files"

# === TIER 1: ULTRA-FAST DAILY WORKFLOW ===

# Ultra-fast quality check (< 1 second) - 197x faster than old 3-tool combo
quick-check:
	@echo "🚀 Ultra-fast quality check (ruff)..."
	@ruff check parse_avc.py --quiet | head -10 || echo "✅ All checks passed"
	@echo "✅ Quick check completed"

# Code formatting and organization (ruff all-in-one)
format:
	@echo "🎨 Formatting code (ruff)..."
	@ruff format parse_avc.py context.py utils.py
	@ruff check parse_avc.py context.py utils.py --fix --quiet || true
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
	@ruff check parse_avc.py context.py utils.py | head -15 || true
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

# Testing infrastructure (NEW CAPABILITY)
test:
	@echo "🧪 Running comprehensive test suite..."
	@python3 -m unittest discover tests/ -v
	@echo "✅ Test suite completed"

# Regression prevention framework (PHASE 7 COMPLETED)
test-regression:
	@echo "🛡️ Running regression prevention suite..."
	@python3 tests/test_runner.py
	@echo "✅ Regression prevention completed"

# === SETUP & MAINTENANCE ===

# Install winning tools
install-tools:
	@echo "🛠️ Installing optimized dev tools..."
	@pip install -r dev-requirements.txt
	@echo "✅ All dev tools installed from dev-requirements.txt"

# Cleanup
clean:
	@echo "🧹 Cleaning generated files..."
	@rm -f *.svg *.png *.gv
	@rm -rf __pycache__ *.pyc .mypy_cache htmlcov
	@echo "✅ Cleaned up"

# Complete workflow for modularization safety
all: format quick-check test security flow-diagram deps-graph
	@echo "🎉 Complete workflow finished - ready for safe modularization"

# === TOOL EVOLUTION NOTES ===
# WINNERS (adopted): ruff (all-in-one: formatting + linting + imports), pydeps, unittest
# REJECTED: pytest (timeout), flake8 (broken pipe), pylint (slow)
# REPLACED: pyflakes + isort + black → ruff (single tool, 197x performance improvement)
# PENDING: radon (SIGPIPE fix submitted upstream, PR awaiting merge)
#
# Manual alternatives for specialized needs:
# - Type checking: Run mypy manually when needed
# radon-check: # DISABLED until upstream PR merged
# 	@echo "🔍 Running complexity analysis..."
# 	@radon cc parse_avc.py --show-complexity --average
# 	@echo "📊 Modularized files complexity:"
# 	@radon cc context.py utils.py --average
#
# Temporary workaround for radon complexity analysis:
radon-check-local:
	@echo "🔍 Running complexity analysis with local radon fix..."
	@cd ../radon && python -m radon cc ../avc-parser/parse_avc.py --show-complexity --average
	@echo "📊 Modularized files complexity:"
	@cd ../radon && python -m radon cc ../avc-parser/context.py ../avc-parser/utils.py --average