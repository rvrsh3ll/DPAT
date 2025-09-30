#!/usr/bin/env python3
"""
Sample data test runner for DPAT.

This script runs integration tests using the actual sample data files
from the sample_data directory.
"""

import unittest
import sys
from pathlib import Path

# Add the parent directory to the path so we can import dpat
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def run_sample_data_tests():
    """Run sample data integration tests."""
    # Add the project root to the path
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    # Discover sample data tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName('tests.integration.test_sample_data')
    
    # Create test runner
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout
    )
    
    # Run tests
    result = runner.run(suite)
    
    return result

def check_sample_data_files():
    """Check if sample data files exist."""
    # Get the project root directory (DPAT directory)
    project_root = Path(__file__).parent.parent
    sample_data_dir = project_root / "sample_data"
    
    required_files = [
        "customer.ntds",
        "oclHashcat.pot", 
        "Domain Admins.txt",
        "Enterprise Admins.txt",
        "Enterprise Admins PowerView Output.txt"
    ]
    
    missing_files = []
    for filename in required_files:
        file_path = sample_data_dir / filename
        if not file_path.exists():
            missing_files.append(str(file_path))
    
    if missing_files:
        print("❌ Missing sample data files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("\nPlease ensure all sample data files are present before running tests.")
        return False
    
    print("✅ All sample data files found:")
    for filename in required_files:
        file_path = sample_data_dir / filename
        print(f"   - {file_path}")
    
    return True

def main():
    """Main test runner function."""
    print("🧪 DPAT Sample Data Integration Tests")
    print("=" * 50)
    
    # Check if sample data files exist
    if not check_sample_data_files():
        return 1
    
    print("\n🔍 Running sample data integration tests...")
    
    # Run tests
    result = run_sample_data_tests()
    
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
