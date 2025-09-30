"""
Test configuration and setup for DPAT test suite.

This module provides common test utilities, fixtures, and configuration
for testing the Domain Password Audit Tool.
"""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, Optional
import sqlite3
import logging

# Configure test logging
logging.basicConfig(level=logging.WARNING)  # Reduce noise during tests


class TestConfig:
    """Test configuration and utilities."""
    
    def __init__(self):
        self.test_dir = Path(__file__).parent
        self.fixtures_dir = self.test_dir / "fixtures"
        self.temp_dir = None
        
    def setup_temp_dir(self) -> Path:
        """Create a temporary directory for test files."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="dpat_test_"))
        return self.temp_dir
    
    def cleanup_temp_dir(self):
        """Clean up temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
    
    def get_fixture_path(self, filename: str) -> Path:
        """Get path to a test fixture file."""
        return self.fixtures_dir / filename


class TestDataGenerator:
    """Generate test data for DPAT testing."""
    
    @staticmethod
    def create_sample_ntds_data() -> List[str]:
        """Create sample NTDS data for testing."""
        return [
            "DOMAIN\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\user2:1002:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
            "DOMAIN\\admin:1003:aad3b435b51404eeaad3b435b51404ee:098f6bcd4621d373cade4e832627b4f6::::",
            "DOMAIN\\machine$:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\krbtgt:1005:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\user1_history0:1006:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\user1_history1:1007:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
        ]
    
    @staticmethod
    def create_sample_cracked_data() -> List[str]:
        """Create sample cracked password data for testing."""
        return [
            "31d6cfe0d16ae931b73c59d7e0c089c0:",
            "5d41402abc4b2a76b9719d911017c592:hello",
            "098f6bcd4621d373cade4e832627b4f6:admin123",
            "aad3b435b51404eeaad3b435b51404ee:password",
        ]
    
    @staticmethod
    def create_sample_group_data() -> Dict[str, List[str]]:
        """Create sample group membership data for testing."""
        return {
            "Domain Admins": [
                "DOMAIN\\admin",
                "DOMAIN\\admin2"
            ],
            "Enterprise Admins": [
                "DOMAIN\\admin",
                "DOMAIN\\superadmin"
            ],
            "Regular Users": [
                "DOMAIN\\user1",
                "DOMAIN\\user2",
                "DOMAIN\\user3"
            ]
        }
    
    @staticmethod
    def create_sample_kerberoast_data() -> List[str]:
        """Create sample Kerberoast data for testing."""
        return [
            "DOMAIN\\service1:1008:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
            "DOMAIN\\service2:1009:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
        ]


class DatabaseTestHelper:
    """Helper class for database testing."""
    
    @staticmethod
    def create_test_database(db_path: str, group_names: Optional[List[str]] = None) -> sqlite3.Connection:
        """Create a test database with the DPAT schema."""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create main table
        cursor.execute('''
            CREATE TABLE hash_infos (
                username_full text collate nocase,
                username text collate nocase,
                lm_hash text,
                lm_hash_left text,
                lm_hash_right text,
                nt_hash text,
                password text,
                lm_pass_left text,
                lm_pass_right text,
                only_lm_cracked boolean,
                history_index int,
                history_base_username text
            )
        ''')
        
        # Create indexes
        indexes = [
            "CREATE INDEX index_nt_hash ON hash_infos (nt_hash)",
            "CREATE INDEX index_lm_hash_left ON hash_infos (lm_hash_left)",
            "CREATE INDEX index_lm_hash_right ON hash_infos (lm_hash_right)",
            "CREATE INDEX lm_hash ON hash_infos (lm_hash)",
            "CREATE INDEX username ON hash_infos (username)"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        # Create group columns
        if group_names:
            for group_name in group_names:
                sql = f'ALTER TABLE hash_infos ADD COLUMN "{group_name}" boolean'
                cursor.execute(sql)
        
        conn.commit()
        return conn
    
    @staticmethod
    def populate_test_database(conn: sqlite3.Connection, test_data: List[Dict]):
        """Populate test database with sample data."""
        cursor = conn.cursor()
        
        for row in test_data:
            cursor.execute('''
                INSERT INTO hash_infos 
                (username_full, username, lm_hash, lm_hash_left, lm_hash_right, 
                 nt_hash, password, history_index, history_base_username) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row.get('username_full', ''),
                row.get('username', ''),
                row.get('lm_hash', ''),
                row.get('lm_hash_left', ''),
                row.get('lm_hash_right', ''),
                row.get('nt_hash', ''),
                row.get('password', ''),
                row.get('history_index', -1),
                row.get('history_base_username', '')
            ))
        
        conn.commit()


class TestFileManager:
    """Manage test files and cleanup."""
    
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.created_files = []
    
    def create_file(self, filename: str, content: List[str]) -> Path:
        """Create a test file with content."""
        file_path = self.temp_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            for line in content:
                f.write(line + '\n')
        self.created_files.append(file_path)
        return file_path
    
    def create_group_files(self, group_data: Dict[str, List[str]]) -> Dict[str, Path]:
        """Create group membership files."""
        group_files = {}
        for group_name, members in group_data.items():
            filename = f"{group_name}.txt"
            file_path = self.create_file(filename, members)
            group_files[group_name] = file_path
        return group_files
    
    def cleanup(self):
        """Clean up all created files."""
        for file_path in self.created_files:
            if file_path.exists():
                file_path.unlink()


class DPATTestCase(unittest.TestCase):
    """Base test case class for DPAT tests."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_config = TestConfig()
        self.temp_dir = self.test_config.setup_temp_dir()
        self.file_manager = TestFileManager(self.temp_dir)
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        self.file_manager.cleanup()
        self.test_config.cleanup_temp_dir()
    
    def assert_file_exists(self, file_path: Path, msg: str = None):
        """Assert that a file exists."""
        self.assertTrue(file_path.exists(), msg or f"File {file_path} does not exist")
    
    def assert_file_contains(self, file_path: Path, content: str, msg: str = None):
        """Assert that a file contains specific content."""
        self.assert_file_exists(file_path)
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
            self.assertIn(content, file_content, msg or f"File {file_path} does not contain '{content}'")
    
    def assert_database_has_records(self, conn: sqlite3.Connection, table: str, count: int, msg: str = None):
        """Assert that a database table has a specific number of records."""
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        actual_count = cursor.fetchone()[0]
        self.assertEqual(actual_count, count, msg or f"Expected {count} records in {table}, got {actual_count}")


# Test fixtures and sample data
SAMPLE_NTDS_DATA = TestDataGenerator.create_sample_ntds_data()
SAMPLE_CRACKED_DATA = TestDataGenerator.create_sample_cracked_data()
SAMPLE_GROUP_DATA = TestDataGenerator.create_sample_group_data()
SAMPLE_KERBEROAST_DATA = TestDataGenerator.create_sample_kerberoast_data()
