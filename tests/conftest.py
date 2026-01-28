"""
Shared pytest fixtures for MCP Sentinel tests.
"""

import sys
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_tools_call_message() -> dict:
    """A basic tools/call message for testing."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "test-123",
        "params": {
            "name": "query_database",
            "arguments": {
                "query": "SELECT * FROM users"
            }
        }
    }


@pytest.fixture
def sample_tools_call_with_limit() -> dict:
    """A tools/call message with LIMIT clause."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": "test-456",
        "params": {
            "name": "query_database",
            "arguments": {
                "query": "SELECT * FROM users LIMIT 10"
            }
        }
    }


@pytest.fixture
def sample_non_tools_message() -> dict:
    """A non-tools/call message (should pass through)."""
    return {
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": "init-001",
        "params": {}
    }


@pytest.fixture
def sample_policy() -> dict:
    """A sample security policy for testing."""
    return {
        "rules": [
            {
                "id": "test-exfiltration",
                "name": "Test Exfiltration Prevention",
                "description": "Blocks SELECT without LIMIT",
                "target_tool": "query_database",
                "target_argument": "query",
                "conditions": [
                    {"operator": "contains", "value": "SELECT", "ignore_case": True},
                    {"operator": "not_contains", "value": "LIMIT", "ignore_case": True}
                ],
                "match_type": "all",
                "action": "block"
            }
        ]
    }


@pytest.fixture
def wildcard_policy() -> dict:
    """A policy with wildcard tool matching."""
    return {
        "rules": [
            {
                "id": "wildcard-test",
                "name": "Wildcard Match",
                "target_tool": "*_database",
                "target_argument": "query",
                "conditions": [
                    {"operator": "contains", "value": "DROP", "ignore_case": True}
                ],
                "action": "block"
            }
        ]
    }


@pytest.fixture
def regex_policy() -> dict:
    """A policy with regex condition."""
    return {
        "rules": [
            {
                "id": "regex-test",
                "name": "Regex Match",
                "target_tool": "query_database",
                "target_argument": "query",
                "conditions": [
                    {"operator": "regex", "value": r"SELECT\s+\*\s+FROM", "ignore_case": True}
                ],
                "action": "block"
            }
        ]
    }
