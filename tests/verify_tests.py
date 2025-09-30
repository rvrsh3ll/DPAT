#!/usr/bin/env python3
"""
Simple test verification script for DPAT test suite.

This script runs a basic verification to ensure the test suite is properly
configured and can discover and run tests.
"""

import sys
import unittest
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """Test that all required modules can be imported."""
    try:
        from tests import TestConfig, TestDataGenerator, DPATTestCase
        from tests.unit.test_core import TestConfig as UnitTestConfig
        from tests.integration.test_integration import TestNTDSProcessingIntegration
        print("✅ All test modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_discovery():
    """Test that tests can be discovered."""
    try:
        loader = unittest.TestLoader()
        suite = loader.discover('tests', pattern='test_*.py')
        test_count = suite.countTestCases()
        print(f"✅ Discovered {test_count} test cases")
        return test_count > 0
    except Exception as e:
        print(f"❌ Test discovery error: {e}")
        return False

def test_sample_data():
    """Test that sample data can be generated."""
    try:
        from tests import TestDataGenerator
        generator = TestDataGenerator()
        
        ntds_data = generator.create_sample_ntds_data()
        cracked_data = generator.create_sample_cracked_data()
        group_data = generator.create_sample_group_data()
        
        print(f"✅ Generated sample data:")
        print(f"   - NTDS entries: {len(ntds_data)}")
        print(f"   - Cracked entries: {len(cracked_data)}")
        print(f"   - Groups: {len(group_data)}")
        
        return len(ntds_data) > 0 and len(cracked_data) > 0 and len(group_data) > 0
    except Exception as e:
        print(f"❌ Sample data generation error: {e}")
        return False

def test_basic_functionality():
    """Test basic DPAT functionality."""
    try:
        from dpat import Config, calculate_percentage, strtobool
        
        # Test Config
        config = Config(
            ntds_file="test.ntds",
            cracked_file="test.pot",
            min_password_length=8
        )
        print("✅ Config creation works")
        
        # Test utility functions
        percentage = calculate_percentage(25, 100)
        assert percentage == 25.0, f"Expected 25.0, got {percentage}"
        print("✅ Percentage calculation works")
        
        bool_val = strtobool("true")
        assert bool_val == True, f"Expected True, got {bool_val}"
        print("✅ String to boolean conversion works")
        
        return True
    except Exception as e:
        print(f"❌ Basic functionality test error: {e}")
        return False

def main():
    """Run all verification tests."""
    print("🧪 DPAT Test Suite Verification")
    print("=" * 40)
    
    tests = [
        ("Import Tests", test_imports),
        ("Test Discovery", test_discovery),
        ("Sample Data Generation", test_sample_data),
        ("Basic Functionality", test_basic_functionality),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} failed")
    
    print("\n" + "=" * 40)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All verification tests passed! Test suite is ready.")
        return 0
    else:
        print("⚠️  Some verification tests failed. Check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
