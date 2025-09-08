#!/usr/bin/env python3
"""
Run code quality checks and optionally fix issues.
Usage: python run_checks.py [--fix] [files...]
"""

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple


class CodeFixer:
    """Handles automatic code fixes."""

    def __init__(self, files: List[str]):
        self.files = files
        self.fixed_count = 0

    def remove_unused_imports(self, content: str) -> str:
        """Remove unused imports from the code."""
        try:
            tree = ast.parse(content)
            imports = set()
            used = set()

            # Collect imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.add(name.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for name in node.names:
                        imports.add(f"{module}.{name.name}" if module else name.name)

                # Collect usage
                elif isinstance(node, ast.Name):
                    used.add(node.id)
                elif isinstance(node, ast.Attribute):
                    parts = []
                    current = node
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                        used.add(".".join(reversed(parts)))

            # Remove unused imports
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                if line.strip().startswith(("import ", "from ")):
                    # Skip line if it contains only unused imports
                    if not any(u in line for u in used):
                        continue
                new_lines.append(line)

            return "\n".join(new_lines)
        except SyntaxError:
            return content

    def add_missing_docstrings(self, content: str) -> str:
        """Add docstring templates for functions/classes missing them."""
        try:
            tree = ast.parse(content)
            lines = content.split("\n")
            insertions = []

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    # Check if docstring exists
                    if not ast.get_docstring(node):
                        # Create docstring template
                        if isinstance(node, ast.ClassDef):
                            doc = f'"""\n    {node.name}: Class description.\n    """'
                        else:
                            args = [a.arg for a in node.args.args if a.arg != "self"]
                            returns = "None"
                            for child in ast.walk(node):
                                if isinstance(child, ast.Return) and child.value:
                                    returns = "Any"
                                    break
                            doc = f'"""\n    {node.name}: Function description.\n\n'
                            if args:
                                doc += "    Args:\n"
                                for arg in args:
                                    doc += f"        {arg}: Description\n"
                            doc += f'    Returns:\n        {returns}\n    """'

                        # Insert after definition line
                        insertions.append((node.lineno, " " * 4 + doc))

            # Apply insertions from bottom to top
            for line_no, text in sorted(insertions, reverse=True):
                lines.insert(line_no, text)

            return "\n".join(lines)
        except SyntaxError:
            return content

    def ensure_init_files(self) -> None:
        """Ensure __init__.py exists in all Python package directories."""
        for file in self.files:
            path = Path(file)
            if path.is_file() and path.suffix == ".py":
                package_dir = path.parent
                init_file = package_dir / "__init__.py"
                if not init_file.exists() and list(package_dir.glob("*.py")):
                    init_file.touch()
                    print(f"✨ Created {init_file}")
                    self.fixed_count += 1

    def fix_type_annotations(self, content: str) -> str:
        """Fix common type annotation issues."""
        # Replace List[] with list, Dict[] with dict etc. when not from typing
        content = re.sub(r"(?<!typing\.)(List|Dict|Set|Tuple)\[", r"list[", content)

        # Add Optional[] for parameters with None default
        def add_optional(match):
            type_ann = match.group(1)
            if "Optional[" not in type_ann and "Union[" not in type_ann:
                return f": Optional[{type_ann}] = None"
            return match.group(0)

        content = re.sub(r": ([^=\n]+) = None", add_optional, content)

        return content

    def fix_file(self, file: str) -> bool:
        """Apply all fixes to a single file."""
        try:
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()

            original = content

            # Apply fixes
            content = self.remove_unused_imports(content)
            content = self.add_missing_docstrings(content)
            content = self.fix_type_annotations(content)

            if content != original:
                with open(file, "w", encoding="utf-8") as f:
                    f.write(content)
                self.fixed_count += 1
                return True

            return False
        except Exception as e:
            print(f"⚠️  Error fixing {file}: {e}")
            return False


def run_command(cmd: List[str], description: str) -> Tuple[bool, str]:
    """Run a command and return success status and output."""
    print(f"\n=== Running {description} ===")
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + (f"\nErrors:\n{result.stderr}" if result.stderr else "")
    print(output)
    return result.returncode == 0, output


def fix_issues(files: List[str]) -> bool:
    """Attempt to automatically fix formatting and import issues."""
    success = True
    fixed = False

    # Fix imports with isort
    ok, _ = run_command(["isort", "--profile=black", "--line-length=100"] + files, "isort (fixing)")
    if not ok:
        print("⚠️  Some import issues couldn't be fixed automatically")
    else:
        fixed = True

    # Fix formatting with black
    ok, _ = run_command(["black", "--line-length=100"] + files, "black (fixing)")
    if not ok:
        print("⚠️  Some formatting issues couldn't be fixed automatically")
    else:
        fixed = True

    if fixed:
        print("✅ Applied automatic fixes. Please review the changes!")
    return success


def check_code_quality(files: List[str], fix: bool = False) -> bool:
    """Run all code quality checks and optionally fix issues."""
    success = True
    needs_fixing = False

    # First pass: Check everything
    print("🔍 Checking code quality...")

    # Check imports
    ok, output = run_command(
        ["isort", "--check", "--diff", "--profile=black", "--line-length=100"] + files,
        "isort (check)",
    )
    if not ok:
        needs_fixing = True
        success = False

    # Check formatting
    ok, output = run_command(
        ["black", "--check", "--diff", "--line-length=100"] + files, "black (check)"
    )
    if not ok:
        needs_fixing = True
        success = False

    # Run flake8 (can't be auto-fixed)
    ok, output = run_command(["flake8", "--max-line-length=100"] + files, "flake8")
    if not ok:
        success = False
        print("❌ Found style issues that need manual fixing")

    # Run mypy (can't be auto-fixed)
    ok, output = run_command(["mypy"] + files, "mypy")
    if not ok:
        success = False
        print("❌ Found type issues that need manual fixing")

    # If issues were found and --fix was specified, try to fix them
    if needs_fixing and fix:
        print("\n🔧 Attempting to fix formatting and import issues...")
        fix_issues(files)
        # Note: Keep original success value as some issues might need manual fixing

    # Run tests
    ok, _ = run_command(
        ["pytest", "-v", "--cov=.", "--cov-report=term-missing", "tests/"], "pytest"
    )
    if not ok:
        success = False
        print("❌ Some tests failed")

    return success


def main():
    parser = argparse.ArgumentParser(
        description="Run code quality checks and optionally fix issues."
    )
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues automatically")
    parser.add_argument("files", nargs="*", help="Files to check (default: all Python files)")
    args = parser.parse_args()

    # Get files to check (all Python files if not specified)
    files = args.files if args.files else [str(f) for f in Path(".").glob("**/*.py")]

    success = check_code_quality(files, fix=args.fix)

    if success:
        print("\n✨ All checks passed!")
        sys.exit(0)
    else:
        if not args.fix:
            print("\n💡 Tip: Run with --fix to attempt automatic fixes")
        sys.exit(1)


if __name__ == "__main__":
    main()
