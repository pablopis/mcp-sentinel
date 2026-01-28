"""
Unit tests for policy evaluation in MCP Sentinel.
"""

import pytest

import policy


class TestCheckCondition:
    """Tests for the check_condition function."""

    def test_contains_match(self) -> None:
        """Test contains operator with matching value."""
        condition = {"operator": "contains", "value": "SELECT"}
        assert policy.check_condition("SELECT * FROM users", condition) is True

    def test_contains_no_match(self) -> None:
        """Test contains operator with non-matching value."""
        condition = {"operator": "contains", "value": "DELETE"}
        assert policy.check_condition("SELECT * FROM users", condition) is False

    def test_contains_ignore_case(self) -> None:
        """Test contains operator with case insensitivity."""
        condition = {"operator": "contains", "value": "select", "ignore_case": True}
        assert policy.check_condition("SELECT * FROM users", condition) is True

    def test_not_contains_match(self) -> None:
        """Test not_contains when value is absent."""
        condition = {"operator": "not_contains", "value": "LIMIT"}
        assert policy.check_condition("SELECT * FROM users", condition) is True

    def test_not_contains_no_match(self) -> None:
        """Test not_contains when value is present."""
        condition = {"operator": "not_contains", "value": "SELECT"}
        assert policy.check_condition("SELECT * FROM users", condition) is False

    def test_equals_match(self) -> None:
        """Test equals operator with exact match."""
        condition = {"operator": "equals", "value": "DROP TABLE"}
        assert policy.check_condition("DROP TABLE", condition) is True

    def test_equals_no_match(self) -> None:
        """Test equals operator with non-matching value."""
        condition = {"operator": "equals", "value": "DROP TABLE"}
        assert policy.check_condition("DROP TABLE users", condition) is False

    def test_regex_match(self) -> None:
        """Test regex operator with matching pattern."""
        condition = {"operator": "regex", "value": r"SELECT\s+\*\s+FROM"}
        assert policy.check_condition("SELECT * FROM users", condition) is True

    def test_regex_no_match(self) -> None:
        """Test regex operator with non-matching pattern."""
        condition = {"operator": "regex", "value": r"^DELETE"}
        assert policy.check_condition("SELECT * FROM users", condition) is False

    def test_regex_ignore_case(self) -> None:
        """Test regex operator with case insensitivity."""
        condition = {"operator": "regex", "value": r"select", "ignore_case": True}
        assert policy.check_condition("SELECT * FROM users", condition) is True

    def test_regex_invalid_pattern(self) -> None:
        """Test regex operator with invalid pattern returns False."""
        condition = {"operator": "regex", "value": r"[invalid("}
        assert policy.check_condition("any value", condition) is False

    def test_unknown_operator(self) -> None:
        """Test unknown operator returns False."""
        condition = {"operator": "unknown", "value": "test"}
        assert policy.check_condition("test value", condition) is False


class TestEvaluatePolicy:
    """Tests for the evaluate_policy function."""

    def test_non_tools_call_passes(self, sample_non_tools_message: dict) -> None:
        """Test that non-tools/call messages pass through."""
        policy.CURRENT_POLICY = {"rules": []}
        result = policy.evaluate_policy(sample_non_tools_message)
        assert result is None

    def test_empty_rules_passes(self, sample_tools_call_message: dict) -> None:
        """Test that empty policy allows all calls."""
        policy.CURRENT_POLICY = {"rules": []}
        result = policy.evaluate_policy(sample_tools_call_message)
        assert result is None

    def test_matching_rule_blocks(
        self,
        sample_tools_call_message: dict,
        sample_policy: dict
    ) -> None:
        """Test that matching rule blocks the request."""
        policy.CURRENT_POLICY = sample_policy
        result = policy.evaluate_policy(sample_tools_call_message)
        assert result == "Test Exfiltration Prevention"

    def test_with_limit_passes(
        self,
        sample_tools_call_with_limit: dict,
        sample_policy: dict
    ) -> None:
        """Test that query with LIMIT is allowed."""
        policy.CURRENT_POLICY = sample_policy
        result = policy.evaluate_policy(sample_tools_call_with_limit)
        assert result is None

    def test_wildcard_tool_matching(self, wildcard_policy: dict) -> None:
        """Test wildcard pattern matching for tools."""
        policy.CURRENT_POLICY = wildcard_policy
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-wild",
            "params": {
                "name": "query_database",
                "arguments": {"query": "DROP TABLE users"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result == "Wildcard Match"

    def test_wildcard_no_match(self, wildcard_policy: dict) -> None:
        """Test wildcard doesn't match unrelated tools."""
        policy.CURRENT_POLICY = wildcard_policy
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-wild",
            "params": {
                "name": "send_email",
                "arguments": {"body": "DROP TABLE users"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result is None

    def test_regex_rule(self, regex_policy: dict) -> None:
        """Test regex pattern in conditions."""
        policy.CURRENT_POLICY = regex_policy
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-regex",
            "params": {
                "name": "query_database",
                "arguments": {"query": "SELECT * FROM users"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result == "Regex Match"

    def test_missing_argument_passes(self, sample_policy: dict) -> None:
        """Test that missing target_argument allows the call."""
        policy.CURRENT_POLICY = sample_policy
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-missing",
            "params": {
                "name": "query_database",
                "arguments": {"other_arg": "value"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result is None

    def test_allow_action(self) -> None:
        """Test that allow action explicitly permits the call."""
        policy.CURRENT_POLICY = {
            "rules": [
                {
                    "name": "Allow Safe",
                    "target_tool": "safe_tool",
                    "target_argument": "input",
                    "conditions": [],
                    "action": "allow"
                }
            ]
        }
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-allow",
            "params": {
                "name": "safe_tool",
                "arguments": {"input": "anything"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result is None

    def test_hitl_action_returns_prefix(self) -> None:
        """Test that allow_with_approval returns HITL: prefix."""
        policy.CURRENT_POLICY = {
            "rules": [
                {
                    "name": "Approval Required",
                    "target_tool": "dangerous_tool",
                    "target_argument": "action",
                    "conditions": [
                        {"operator": "contains", "value": "DELETE"}
                    ],
                    "action": "allow_with_approval"
                }
            ]
        }
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-hitl",
            "params": {
                "name": "dangerous_tool",
                "arguments": {"action": "DELETE users"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result == "HITL:Approval Required"

    def test_match_type_any(self) -> None:
        """Test match_type: any matches if any condition is true."""
        policy.CURRENT_POLICY = {
            "rules": [
                {
                    "name": "Any Match",
                    "target_tool": "query_database",
                    "target_argument": "query",
                    "conditions": [
                        {"operator": "contains", "value": "DELETE"},
                        {"operator": "contains", "value": "DROP"}
                    ],
                    "match_type": "any",
                    "action": "block"
                }
            ]
        }
        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-any",
            "params": {
                "name": "query_database",
                "arguments": {"query": "DROP TABLE users"}
            }
        }
        result = policy.evaluate_policy(message)
        assert result == "Any Match"


class TestIsDangerous:
    """Tests for the is_dangerous wrapper function."""

    def test_is_dangerous_wrapper(
        self,
        sample_tools_call_message: dict,
        sample_policy: dict
    ) -> None:
        """Test is_dangerous is equivalent to evaluate_policy."""
        policy.CURRENT_POLICY = sample_policy
        result = policy.is_dangerous(sample_tools_call_message)
        assert result == "Test Exfiltration Prevention"
