"""
Test runner and configuration for DPAT test suite.

This module provides the main test runner and configuration for running
the complete DPAT test suite.
"""

import unittest
import sys
import os
from pathlib import Path
import logging

# Add the parent directory to the path so we can import dpat
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure test logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def discover_tests():
    """Discover all test modules."""
    # Get the tests directory
    tests_dir = Path(__file__).parent
    
    # Discover unit tests
    unit_loader = unittest.TestLoader()
    unit_suite = unit_loader.discover(
        start_dir=str(tests_dir / 'unit'),
        pattern='test_*.py',
        top_level_dir=str(tests_dir)
    )
    
    # Discover integration tests
    integration_loader = unittest.TestLoader()
    integration_suite = integration_loader.discover(
        start_dir=str(tests_dir / 'integration'),
        pattern='test_*.py',
        top_level_dir=str(tests_dir)
    )
    
    # Combine all test suites
    all_tests = unittest.TestSuite()
    all_tests.addTest(unit_suite)
    all_tests.addTest(integration_suite)
    
    return all_tests

def run_tests(verbosity=2, failfast=False):
    """Run all tests with the specified verbosity."""
    # Discover tests
    test_suite = discover_tests()
    
    # Create test runner
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=failfast,
        stream=sys.stdout
    )
    
    # Run tests
    result = runner.run(test_suite)
    
    return result

def run_unit_tests_only(verbosity=2, failfast=False):
    """Run only unit tests."""
    tests_dir = Path(__file__).parent
    
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(tests_dir / 'unit'),
        pattern='test_*.py',
        top_level_dir=str(tests_dir)
    )
    
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=failfast,
        stream=sys.stdout
    )
    
    result = runner.run(suite)
    return result

def run_sample_data_tests_only(verbosity=2, failfast=False):
    """Run only sample data integration tests."""
    tests_dir = Path(__file__).parent
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName('tests.integration.test_sample_data')
    
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=failfast,
        stream=sys.stdout
    )
    
    result = runner.run(suite)
    return result

def run_specific_test(test_module, verbosity=2, failfast=False):
    """Run a specific test module."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_module)
    
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=failfast,
        stream=sys.stdout
    )
    
    result = runner.run(suite)
    return result

def main():
    """Main test runner function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run DPAT test suite')
    parser.add_argument(
        '--unit-only',
        action='store_true',
        help='Run only unit tests'
    )
    parser.add_argument(
        '--sample-data-only',
        action='store_true',
        help='Run only sample data integration tests'
    )
    parser.add_argument(
        '--module',
        type=str,
        help='Run specific test module (e.g., tests.unit.test_core)'
    )
    parser.add_argument(
        '--verbosity',
        type=int,
        default=2,
        choices=[0, 1, 2],
        help='Test output verbosity (0=quiet, 1=normal, 2=verbose)'
    )
    parser.add_argument(
        '--failfast',
        action='store_true',
        help='Stop on first failure'
    )
    parser.add_argument(
        '--list-tests',
        action='store_true',
        help='List all available tests without running them'
    )
    
    args = parser.parse_args()
    
    if args.list_tests:
        # List all available tests
        test_suite = discover_tests()
        print(f"Found {test_suite.countTestCases()} test cases:")
        
        def print_tests(suite, indent=0):
            for test in suite:
                if hasattr(test, '_tests'):
                    print_tests(test, indent + 1)
                else:
                    print("  " * indent + str(test))
        
        print_tests(test_suite)
        return 0
    
    # Run tests based on arguments
    if args.module:
        result = run_specific_test(args.module, args.verbosity, args.failfast)
    elif args.unit_only:
        result = run_unit_tests_only(args.verbosity, args.failfast)
    elif args.sample_data_only:
        result = run_sample_data_tests_only(args.verbosity, args.failfast)
    elif args.integration_only:
        result = run_integration_tests_only(args.verbosity, args.failfast)
    else:
        result = run_tests(args.verbosity, args.failfast)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Test Summary:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(main())
