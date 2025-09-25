# Makefile for AVC Parser Quality Tools
# Usage: make <target>

.PHONY: help format flow-diagram flow-focused check install-tools pre-commit-install clean

# Default target
help:
	@echo "Available targets:"
	@echo "  format           - Format code with black"
	@echo "  flow-diagram     - Generate complete function flow diagram (SVG)"
	@echo "  flow-focused     - Generate focused flow diagram from main function"
	@echo "  flow-png         - Generate flow diagrams in PNG format"
	@echo "  check            - Run basic code quality checks"
	@echo "  install-tools    - Install required quality tools"
	@echo "  pre-commit-install - Install pre-commit hooks"
	@echo "  clean            - Remove generated files"
	@echo "  help             - Show this help message"

# Code formatting
format:
	@echo "Formatting code with black..."
	black parse_avc.py --line-length=88

# Flow diagrams
flow-diagram:
	@echo "Generating complete function flow diagram..."
	code2flow parse_avc.py --output avc_parser_flow.svg --language py --skip-parse-errors
	@echo "Generated: avc_parser_flow.svg"

flow-focused:
	@echo "Generating focused flow diagram from main function..."
	code2flow parse_avc.py --output avc_core_flow.svg --language py --target-function main --downstream-depth 3 --skip-parse-errors
	@echo "Generated: avc_core_flow.svg"

flow-png:
	@echo "Generating PNG flow diagrams..."
	code2flow parse_avc.py --output avc_parser_flow.png --language py --skip-parse-errors
	code2flow parse_avc.py --output avc_core_flow.png --language py --target-function main --downstream-depth 3 --skip-parse-errors
	@echo "Generated: avc_parser_flow.png and avc_core_flow.png"

# Quality checks
check:
	@echo "Running basic quality checks..."
	@echo "File line count:"
	@wc -l parse_avc.py
	@echo "Python syntax check:"
	@python3 -m py_compile parse_avc.py && echo "✓ Syntax OK"

# Tool installation
install-tools:
	@echo "Installing development tools..."
	pip install -r dev-requirements.txt

# Pre-commit setup
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	pre-commit install
	@echo "✓ Pre-commit hooks installed"

# Cleanup
clean:
	@echo "Cleaning generated files..."
	rm -f *.svg *.png *.gv
	rm -rf __pycache__ *.pyc
	@echo "✓ Cleaned up"

# Advanced quality tools (commented out - use when needed)
# install-advanced-tools:
#	pip install vulture rope flake8 mypy pylint safety

# check-dead-code:
#	vulture parse_avc.py --min-confidence 80

# type-check:
#	mypy parse_avc.py --ignore-missing-imports