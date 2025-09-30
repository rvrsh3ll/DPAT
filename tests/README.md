# DPAT Test Suite Documentation

## Overview

This comprehensive test suite for the Domain Password Audit Tool (DPAT) provides thorough testing of all functionality, including unit tests, integration tests, and performance tests.

## Test Structure

```
tests/
├── __init__.py                 # Test configuration and utilities
├── run_tests.py               # Main test runner
├── unit/                      # Unit tests
│   ├── __init__.py
│   └── test_core.py          # Core class unit tests
├── integration/               # Integration tests
│   ├── __init__.py
│   └── test_integration.py   # End-to-end workflow tests
└── fixtures/                  # Test data and fixtures
    ├── __init__.py
    └── test_data.py          # Sample data and utilities
```

## Test Categories

### Unit Tests (`tests/unit/`)

Unit tests focus on testing individual classes and methods in isolation:

- **TestConfig**: Configuration dataclass testing
- **TestNTDSProcessor**: NTDS file parsing and processing
- **TestHashProcessor**: Password hashing and cracking logic
- **TestDataSanitizer**: Data sanitization functionality
- **TestHTMLReportBuilder**: HTML report generation
- **TestDatabaseManager**: Database operations and schema
- **TestGroupManager**: Group membership processing
- **TestCrackedPasswordProcessor**: Cracked password processing
- **TestUtilityFunctions**: Utility functions and helpers

### Integration Tests (`tests/integration/`)

Integration tests test complete workflows and component interactions:

- **TestNTDSProcessingIntegration**: Complete NTDS processing workflow
- **TestReportGenerationIntegration**: HTML report generation with real data
- **TestGroupProcessingIntegration**: Group membership processing workflow
- **TestCommandLineIntegration**: Command-line interface testing
- **TestErrorHandlingIntegration**: Error handling and edge cases
- **TestSampleDataIntegration**: Tests using real sample data files

### Test Fixtures (`tests/fixtures/`)

Test fixtures provide realistic test data:

- **Sample NTDS Data**: Realistic NTDS dump format data
- **Sample Cracked Data**: Password cracking results
- **Sample Group Data**: Group membership information
- **Sample Kerberoast Data**: Kerberoast account data
- **Edge Case Data**: Invalid and malformed data for error testing
- **Performance Data**: Large datasets for performance testing

## Running Tests

### Using the Test Runner

```bash
# Run all tests
python tests/run_tests.py

# Run only unit tests
python tests/run_tests.py --unit-only

# Run only sample data tests
python tests/run_tests.py --sample-data-only

# Run with verbose output
python tests/run_tests.py --verbosity 2

# Stop on first failure
python tests/run_tests.py --failfast

# List all available tests
python tests/run_tests.py --list-tests
```

### Using pytest

```bash
# Run all tests
pytest

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run only sample data tests
python tests/run_tests.py --sample-data-only

# Run sample data tests with pytest
pytest tests/integration/test_sample_data.py

# Run specific test file
pytest tests/unit/test_core.py

# Run with coverage
pytest --cov=dpat --cov-report=html

# Run with verbose output
pytest -v

# Run specific test method
pytest tests/unit/test_core.py::TestConfig::test_config_creation
```

### Using unittest directly

```bash
# Run all tests
python -m unittest discover tests

# Run specific test module
python -m unittest tests.unit.test_core

# Run with verbose output
python -m unittest -v tests.unit.test_core
```

## Sample Data Tests

The test suite includes comprehensive integration tests that use the actual sample data files from the `sample_data` directory:

### Required Sample Data Files
- `customer.ntds` - Real NTDS dump with multiple domains
- `oclHashcat.pot` - Real password cracking results
- `Domain Admins.txt` - Domain Admins group membership
- `Enterprise Admins.txt` - Enterprise Admins group membership  
- `Enterprise Admins PowerView Output.txt` - PowerView formatted group data

### Sample Data Test Features
- **Real-world data processing**: Tests with actual NTDS dumps and cracked passwords
- **Multi-domain analysis**: Tests with child.domain.com, parent.domain.com, and sister.domain.com
- **Group membership processing**: Tests with both standard and PowerView formatted group files
- **Report generation**: Tests HTML report generation with real data
- **Statistics analysis**: Tests password statistics and domain-specific analysis
- **Command line execution**: Tests command line interface with real files

### Running Sample Data Tests

```bash
# Run sample data tests only
python tests/run_tests.py --sample-data-only

# Run sample data tests with pytest
pytest tests/integration/test_sample_data.py

# Run sample data tests with dedicated runner
python tests/run_sample_data_tests.py
```

### Sample Data Test Cases
- `test_sample_data_ntds_processing` - Process customer.ntds file
- `test_sample_data_with_groups` - Process with Domain Admins and Enterprise Admins groups
- `test_sample_data_powerview_format` - Process PowerView formatted group file
- `test_sample_data_report_generation` - Generate HTML reports with real data
- `test_sample_data_sanitized_reports` - Test sanitized report generation
- `test_sample_data_statistics` - Test statistics generation
- `test_sample_data_domain_analysis` - Test domain-specific analysis
- `test_sample_data_command_line_execution` - Test command line execution
- `test_sample_data_with_groups_command_line` - Test command line with groups

## Test Data

### Sample NTDS Data

The test suite includes realistic NTDS data with:

- Regular user accounts
- Machine accounts (for filtering tests)
- krbtgt account (for filtering tests)
- Password history entries
- Empty password hashes
- LM hash disabled accounts
- Different domain accounts

### Sample Cracked Data

Cracked password data includes:

- NT hash cracking results
- LM hash cracking results
- Hex encoded passwords
- Empty passwords
- Special character passwords

### Sample Group Data

Group membership data includes:

- Domain Admins
- Enterprise Admins
- Regular Users
- Service Accounts
- Power Users

## Test Configuration

### Environment Setup

Tests automatically create temporary directories and files, so no manual setup is required. Each test:

1. Creates a temporary directory
2. Generates test files with sample data
3. Runs the test
4. Cleans up temporary files

### Test Isolation

Each test is completely isolated:

- Uses separate temporary directories
- Creates fresh database connections
- No shared state between tests
- Automatic cleanup after each test

### Mocking and Stubbing

Tests use Python's `unittest.mock` for:

- File system operations
- Database connections
- External dependencies
- Error conditions

## Test Coverage

The test suite aims for comprehensive coverage of:

- **Core Functionality**: All main classes and methods
- **Error Handling**: Invalid input, missing files, database errors
- **Edge Cases**: Empty data, malformed input, special characters
- **Integration**: Complete workflows from input to output
- **Performance**: Large dataset handling
- **Security**: Data sanitization and validation

## Adding New Tests

### Unit Tests

1. Create test methods in the appropriate test class
2. Use descriptive test method names starting with `test_`
3. Follow the Arrange-Act-Assert pattern
4. Use appropriate assertions (`assertEqual`, `assertTrue`, etc.)
5. Test both success and failure cases

### Integration Tests

1. Create test methods that test complete workflows
2. Use real test data files
3. Verify end-to-end functionality
4. Test error conditions and edge cases
5. Ensure proper cleanup

### Test Data

1. Add new sample data to `tests/fixtures/test_data.py`
2. Use realistic data that mimics real-world scenarios
3. Include edge cases and error conditions
4. Document the purpose of each dataset

## Continuous Integration

The test suite is designed to work with CI/CD systems:

- No external dependencies required
- Automatic test discovery
- Clear exit codes for success/failure
- Comprehensive logging and reporting
- Fast execution for quick feedback

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure the parent directory is in the Python path
2. **File Not Found**: Check that test data files are created correctly
3. **Database Errors**: Verify database connections are properly closed
4. **Permission Errors**: Ensure temporary directories can be created

### Debug Mode

Run tests with debug logging:

```bash
python tests/run_tests.py --verbosity 2
```

### Test Isolation

If tests are interfering with each other:

1. Check for shared state
2. Ensure proper cleanup in `tearDown` methods
3. Use unique temporary directories
4. Verify database connections are closed

## Performance Testing

The test suite includes performance tests for:

- Large NTDS file processing
- Database operations with many records
- HTML report generation with large datasets
- Memory usage during processing

Run performance tests separately:

```bash
python tests/run_tests.py --module tests.performance
```

## Security Testing

Security-focused tests verify:

- Data sanitization functionality
- Input validation and sanitization
- SQL injection prevention
- File path traversal prevention
- Sensitive data handling

## Future Enhancements

Planned improvements to the test suite:

1. **Property-based Testing**: Using Hypothesis for property-based testing
2. **Mutation Testing**: Using mutmut for mutation testing
3. **Load Testing**: Performance testing with very large datasets
4. **Security Testing**: Automated security vulnerability testing
5. **Cross-platform Testing**: Testing on different operating systems
6. **Docker Integration**: Containerized test environments
7. **Parallel Testing**: Running tests in parallel for faster execution
8. **Test Reporting**: Enhanced HTML and XML test reports
9. **Code Coverage**: Detailed code coverage analysis
10. **Benchmarking**: Performance benchmarking and regression testing
