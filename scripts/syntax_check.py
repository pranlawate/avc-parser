#!/usr/bin/env python3
"""
Syntax Validation Utility

This script validates Python syntax across the entire codebase to catch
syntax errors before they reach users.
"""

import os
import sys
import ast
import py_compile
from pathlib import Path

def check_syntax(file_path):
    """Check syntax of a Python file."""
    try:
        # First try with ast (faster)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        ast.parse(content, filename=str(file_path))

        # Then try with py_compile (more thorough)
        py_compile.compile(file_path, doraise=True)

        return True, None
    except SyntaxError as e:
        return False, f"Line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, str(e)

def main():
    """Check syntax of all Python files in the project."""
    print("🔍 Python Syntax Validation")
    print("=" * 40)

    project_root = Path(__file__).parent.parent
    python_files = []

    # Find all Python files
    for pattern in ["*.py", "**/*.py"]:
        python_files.extend(project_root.glob(pattern))

    # Remove duplicates and sort
    python_files = sorted(list(set(python_files)))

    errors = []
    checked = 0

    for py_file in python_files:
        # Skip test files and virtual environments
        if any(skip in str(py_file) for skip in ['.venv', 'venv', '__pycache__']):
            continue

        print(f"Checking: {py_file.name}")

        is_valid, error_msg = check_syntax(py_file)
        checked += 1

        if is_valid:
            print(f"  ✅ Valid")
        else:
            print(f"  ❌ Error: {error_msg}")
            errors.append((str(py_file), error_msg))

    print(f"\n📊 Results:")
    print(f"  Files checked: {checked}")
    print(f"  Errors found: {len(errors)}")

    if errors:
        print(f"\n❌ Syntax Errors:")
        for file_path, error in errors:
            print(f"  • {file_path}: {error}")
        sys.exit(1)
    else:
        print(f"\n✅ All Python files have valid syntax!")

if __name__ == "__main__":
    main()