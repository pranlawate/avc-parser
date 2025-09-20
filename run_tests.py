#!/usr/bin/env python3
"""
Test runner for AVC Parser

Simple script to run all tests and provide clear output.
"""

import unittest
import sys
import os

def run_tests():
    """Run all tests and return success status."""
    print("🧪 Running AVC Parser Tests")
    print("=" * 50)

    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')

    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        buffer=True
    )

    result = runner.run(suite)

    print("\n" + "=" * 50)

    if result.wasSuccessful():
        print("✅ All tests passed!")
        return True
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors")
        return False

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)