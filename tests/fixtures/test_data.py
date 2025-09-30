"""
Test fixtures and sample data for DPAT testing.

This module provides realistic test data that mimics real-world NTDS dumps
and password cracking results for comprehensive testing.
"""

from pathlib import Path
from typing import List, Dict

# Sample NTDS data (pwdump format)
SAMPLE_NTDS_DATA = [
    # Regular user accounts
    "DOMAIN\\john.doe:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\jane.smith:1002:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
    "DOMAIN\\admin.user:1003:aad3b435b51404eeaad3b435b51404ee:098f6bcd4621d373cade4e832627b4f6::::",
    "DOMAIN\\service.account:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Machine accounts (should be filtered by default)
    "DOMAIN\\WORKSTATION01$:1005:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\SERVER01$:1006:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # krbtgt account (should be filtered by default)
    "DOMAIN\\krbtgt:1007:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Password history entries
    "DOMAIN\\john.doe_history0:1008:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\john.doe_history1:1009:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
    "DOMAIN\\jane.smith_history0:1010:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Empty password hashes
    "DOMAIN\\empty.user:1011:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # LM hash disabled (empty LM hash)
    "DOMAIN\\lm.disabled:1012::31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Different domain
    "OTHERDOMAIN\\user1:1013:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
]

# Sample cracked password data (hashcat.potfile format)
SAMPLE_CRACKED_DATA = [
    # NT hashes
    "31d6cfe0d16ae931b73c59d7e0c089c0:",
    "5d41402abc4b2a76b9719d911017c592:hello",
    "098f6bcd4621d373cade4e832627b4f6:admin123",
    "aad3b435b51404eeaad3b435b51404ee:password",
    
    # LM hashes
    "aad3b435b51404ee:password",
    "aad3b435b51404ee:Password",
    "aad3b435b51404ee:PASSWORD",
    
    # Hex encoded passwords
    "31d6cfe0d16ae931b73c59d7e0c089c0:$HEX[68656c6c6f]",
    "5d41402abc4b2a76b9719d911017c592:$HEX[61646d696e313233]",
    
    # Empty passwords
    "31d6cfe0d16ae931b73c59d7e0c089c0:",
    
    # Special characters
    "098f6bcd4621d373cade4e832627b4f6:pass@word123!",
    "31d6cfe0d16ae931b73c59d7e0c089c0:test\\user",
]

# Sample group membership data
SAMPLE_GROUP_DATA = {
    "Domain Admins": [
        "DOMAIN\\admin.user",
        "DOMAIN\\super.admin",
        "DOMAIN\\admin.user-admin",  # Elevated account
    ],
    "Enterprise Admins": [
        "DOMAIN\\admin.user",
        "DOMAIN\\enterprise.admin",
        "DOMAIN\\admin.user-admin",  # Elevated account
    ],
    "Regular Users": [
        "DOMAIN\\john.doe",
        "DOMAIN\\jane.smith",
        "DOMAIN\\regular.user",
        "DOMAIN\\john.doe-admin",  # Elevated account
    ],
    "Service Accounts": [
        "DOMAIN\\service.account",
        "DOMAIN\\sql.service",
        "DOMAIN\\web.service",
    ],
    "Power Users": [
        "DOMAIN\\power.user1",
        "DOMAIN\\power.user2",
        "DOMAIN\\power.user1-admin",  # Elevated account
    ]
}

# Sample Kerberoast data
SAMPLE_KERBEROAST_DATA = [
    "DOMAIN\\sql.service:1008:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\web.service:1009:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
    "DOMAIN\\exchange.service:1010:aad3b435b51404eeaad3b435b51404ee:098f6bcd4621d373cade4e832627b4f6::::",
    "DOMAIN\\ldap.service:1011:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
]

# Sample account status data
SAMPLE_ACCOUNT_STATUS_DATA = [
    "DOMAIN\\john.doe:enabled",
    "DOMAIN\\jane.smith:enabled",
    "DOMAIN\\admin.user:enabled",
    "DOMAIN\\service.account:enabled",
    "DOMAIN\\disabled.user:disabled",
    "DOMAIN\\locked.user:disabled",
    "DOMAIN\\expired.user:disabled",
]

# Complex test scenarios
COMPLEX_NTDS_DATA = [
    # Multiple domains
    "DOMAIN1\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN2\\user2:1002:aad3b435b51404eeaad3b435b51404ee:5d41402abc4b2a76b9719d911017c592::::",
    
    # Long usernames
    "DOMAIN\\very.long.username.that.exceeds.normal.length:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Special characters in usernames
    "DOMAIN\\user-with-dashes:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\user_with_underscores:1005:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    "DOMAIN\\user.with.dots:1006:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Email format usernames
    "DOMAIN\\user@domain.com:1007:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
    
    # Unicode characters (if supported)
    "DOMAIN\\café:1008:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
]

# Edge case test data
EDGE_CASE_DATA = [
    # Empty lines
    "",
    "   ",
    
    # Invalid formats
    "invalid line",
    "user:hash",
    "user:rid:lm:nt:extra:fields:too:many",
    
    # Malformed hashes
    "DOMAIN\\user1:1001:invalid_lm_hash:invalid_nt_hash::::",
    "DOMAIN\\user2:1002:aad3b435b51404eeaad3b435b51404ee:invalid_nt_hash::::",
    
    # Very long lines
    "DOMAIN\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::" + "x" * 1000,
    
    # Special characters in hashes
    "DOMAIN\\user1:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::::",
]

# Performance test data (large datasets)
def generate_large_ntds_data(count: int = 1000) -> List[str]:
    """Generate large NTDS dataset for performance testing."""
    data = []
    for i in range(count):
        username = f"DOMAIN\\user{i:04d}"
        rid = 1000 + i
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        nt_hash = f"31d6cfe0d16ae931b73c59d7e0c089c{i:02d}"
        data.append(f"{username}:{rid}:{lm_hash}:{nt_hash}::::")
    return data

def generate_large_cracked_data(count: int = 500) -> List[str]:
    """Generate large cracked password dataset for performance testing."""
    data = []
    for i in range(count):
        nt_hash = f"31d6cfe0d16ae931b73c59d7e0c089c{i:02d}"
        password = f"password{i:03d}"
        data.append(f"{nt_hash}:{password}")
    return data

# Test file creation utilities
def create_test_files(temp_dir: Path) -> Dict[str, Path]:
    """Create all test files in a temporary directory."""
    files = {}
    
    # Create NTDS file
    ntds_file = temp_dir / "test.ntds"
    with open(ntds_file, 'w', encoding='utf-8') as f:
        for line in SAMPLE_NTDS_DATA:
            f.write(line + '\n')
    files['ntds'] = ntds_file
    
    # Create cracked file
    cracked_file = temp_dir / "test.pot"
    with open(cracked_file, 'w', encoding='utf-8') as f:
        for line in SAMPLE_CRACKED_DATA:
            f.write(line + '\n')
    files['cracked'] = cracked_file
    
    # Create group files
    group_dir = temp_dir / "groups"
    group_dir.mkdir(exist_ok=True)
    
    for group_name, members in SAMPLE_GROUP_DATA.items():
        group_file = group_dir / f"{group_name}.txt"
        with open(group_file, 'w', encoding='utf-8') as f:
            for member in members:
                f.write(member + '\n')
        files[f'group_{group_name}'] = group_file
    
    # Create Kerberoast file
    kerberoast_file = temp_dir / "kerberoast.txt"
    with open(kerberoast_file, 'w', encoding='utf-8') as f:
        for line in SAMPLE_KERBEROAST_DATA:
            f.write(line + '\n')
    files['kerberoast'] = kerberoast_file
    
    # Create account status file
    status_file = temp_dir / "account_status.txt"
    with open(status_file, 'w', encoding='utf-8') as f:
        for line in SAMPLE_ACCOUNT_STATUS_DATA:
            f.write(line + '\n')
    files['account_status'] = status_file
    
    return files

# Expected test results
EXPECTED_RESULTS = {
    'total_accounts': 4,  # Regular users only (excluding machine accounts and krbtgt)
    'cracked_accounts': 3,  # Based on cracked data
    'cracked_percentage': 75.0,  # 3/4 * 100
    'groups_count': 5,  # Number of groups
    'group_members': {
        'Domain Admins': 3,
        'Enterprise Admins': 3,
        'Regular Users': 4,
        'Service Accounts': 3,
        'Power Users': 3
    }
}

# Test configuration templates
TEST_CONFIGS = {
    'minimal': {
        'ntds_file': 'test.ntds',
        'cracked_file': 'test.pot',
        'min_password_length': 8
    },
    'with_groups': {
        'ntds_file': 'test.ntds',
        'cracked_file': 'test.pot',
        'min_password_length': 8,
        'groups_directory': 'groups/'
    },
    'sanitized': {
        'ntds_file': 'test.ntds',
        'cracked_file': 'test.pot',
        'min_password_length': 8,
        'sanitize_output': True
    },
    'full_options': {
        'ntds_file': 'test.ntds',
        'cracked_file': 'test.pot',
        'min_password_length': 8,
        'groups_directory': 'groups/',
        'sanitize_output': True,
        'include_machine_accounts': True,
        'include_krbtgt': True,
        'kerberoast_file': 'kerberoast.txt'
    }
}
