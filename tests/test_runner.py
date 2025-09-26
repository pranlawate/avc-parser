#!/usr/bin/env python3
"""
Comprehensive Test Runner for AVC Parser

This script provides a complete test suite runner with regression prevention
capabilities, performance monitoring, and detailed reporting.
"""

import unittest
import sys
import os
import time
import subprocess
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestResults:
    """Track and report test execution results."""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0
        self.errors = []
        self.failures = []

    def start_timing(self):
        """Start timing test execution."""
        self.start_time = time.time()

    def stop_timing(self):
        """Stop timing test execution."""
        self.end_time = time.time()

    def get_duration(self):
        """Get test execution duration."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0

    def add_result(self, test_result):
        """Add test result to tracking."""
        self.total_tests = test_result.testsRun
        self.failed_tests = len(test_result.failures)
        self.errors = test_result.errors
        self.failures = test_result.failures
        self.passed_tests = self.total_tests - self.failed_tests - len(self.errors)

    def print_summary(self):
        """Print comprehensive test summary."""
        print(f"\n{'='*70}")
        print(f"AVC Parser Test Suite - Comprehensive Results")
        print(f"{'='*70}")
        print(f"Execution Time: {self.get_duration():.2f} seconds")
        print(f"Total Tests:    {self.total_tests}")
        print(f"Passed:         {self.passed_tests}")
        print(f"Failed:         {self.failed_tests}")
        print(f"Errors:         {len(self.errors)}")
        print(f"Success Rate:   {(self.passed_tests/self.total_tests)*100:.1f}%")

        if self.failures or self.errors:
            print(f"\n{'='*70}")
            print(f"REGRESSION DETECTED - Test Failures Found")
            print(f"{'='*70}")

            if self.failures:
                print(f"\nTest Failures ({len(self.failures)}):")
                for test, traceback in self.failures:
                    print(f"  ❌ {test}")
                    print(f"     {traceback.split('AssertionError:')[-1].strip()}")

            if self.errors:
                print(f"\nTest Errors ({len(self.errors)}):")
                for test, traceback in self.errors:
                    print(f"  💥 {test}")
                    print(f"     {traceback.split('Exception:')[-1].strip()}")
        else:
            print(f"\n✅ ALL TESTS PASSED - No Regressions Detected")

        print(f"{'='*70}")


def discover_and_run_tests():
    """Discover and run all tests with comprehensive reporting."""
    print("🧪 Starting AVC Parser Comprehensive Test Suite...")
    print(f"📁 Test Discovery Path: {Path(__file__).parent}")

    # Initialize test results tracking
    results = TestResults()
    results.start_timing()

    # Create test loader and suite
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern='test_*.py')

    # Create test runner with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        buffer=True
    )

    # Run tests
    print(f"\n🚀 Executing Test Suite...\n")
    test_result = runner.run(suite)

    # Stop timing and record results
    results.stop_timing()
    results.add_result(test_result)

    # Print comprehensive summary
    results.print_summary()

    # Return success/failure for CI/CD integration
    return len(test_result.failures) == 0 and len(test_result.errors) == 0


def run_performance_benchmark():
    """Run basic performance benchmarks for regression detection."""
    print("\n🏃 Running Performance Benchmarks...")

    test_files = [
        "testAVC/multi_AVC.log",
        "testAVC/network_AVC.log"
    ]

    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"  📊 Benchmarking: {test_file}")
            start_time = time.time()

            result = subprocess.run(
                [sys.executable, "parse_avc.py", "--file", test_file, "--json"],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )

            duration = time.time() - start_time

            if result.returncode == 0:
                print(f"    ⏱️  Processing time: {duration:.3f}s")
                print(f"    ✅ Status: SUCCESS")
            else:
                print(f"    ❌ Status: FAILED")
                print(f"    📝 Error: {result.stderr[:100]}...")
        else:
            print(f"  ⚠️  Skipping {test_file} (not found)")


def check_code_quality():
    """Run code quality checks for regression prevention."""
    print("\n🔍 Running Code Quality Checks...")

    quality_tools = [
        ("ruff", ["ruff", "check", "."]),
        ("ruff format check", ["ruff", "format", "--check", "."]),
    ]

    for tool_name, command in quality_tools:
        print(f"  🛠️  Running {tool_name}...")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )

            if result.returncode == 0:
                print(f"    ✅ {tool_name}: PASSED")
            else:
                print(f"    ❌ {tool_name}: ISSUES FOUND")
                if result.stdout:
                    print(f"    📝 Output: {result.stdout[:200]}...")

        except FileNotFoundError:
            print(f"    ⚠️  {tool_name}: Not available (install with pip)")


def main():
    """Main test runner entry point."""
    print("🎯 AVC Parser - Comprehensive Test & Regression Prevention Suite")
    print("=" * 70)

    # Change to project root
    project_root = os.path.dirname(os.path.dirname(__file__))
    os.chdir(project_root)

    # Run comprehensive tests
    tests_passed = discover_and_run_tests()

    # Run performance benchmarks
    run_performance_benchmark()

    # Run code quality checks
    check_code_quality()

    # Final status
    print(f"\n{'='*70}")
    if tests_passed:
        print("🎉 REGRESSION PREVENTION: ALL SYSTEMS GO")
        print("   No regressions detected - Safe to deploy!")
        exit_code = 0
    else:
        print("🚨 REGRESSION PREVENTION: ISSUES DETECTED")
        print("   Please fix failing tests before deployment!")
        exit_code = 1

    print(f"{'='*70}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())