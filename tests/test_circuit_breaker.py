"""
Unit tests for circuit breaker functionality in MCP Sentinel.
"""

import datetime
import time
from unittest.mock import patch

import pytest

import gateway


class TestCheckCircuitBreaker:
    """Tests for the check_circuit_breaker function."""

    def setup_method(self) -> None:
        """Reset circuit breaker state before each test."""
        gateway.TOOL_CALL_TRACKER.clear()

    def test_first_call_passes(self) -> None:
        """Test that first call to a tool is allowed."""
        result = gateway.check_circuit_breaker("test_tool")
        assert result is None

    def test_under_limit_passes(self) -> None:
        """Test that calls under the limit are allowed."""
        for _ in range(gateway.MAX_CALLS_PER_TOOL - 1):
            result = gateway.check_circuit_breaker("test_tool")
            assert result is None

    def test_at_limit_blocks(self) -> None:
        """Test that reaching the limit blocks further calls."""
        # Make MAX_CALLS_PER_TOOL calls
        for _ in range(gateway.MAX_CALLS_PER_TOOL):
            gateway.check_circuit_breaker("test_tool")

        # Next call should be blocked
        result = gateway.check_circuit_breaker("test_tool")
        assert result is not None
        assert "Circuit Breaker" in result
        assert "test_tool" in result

    def test_different_tools_independent(self) -> None:
        """Test that different tools have independent limits."""
        # Fill up tool_a
        for _ in range(gateway.MAX_CALLS_PER_TOOL):
            gateway.check_circuit_breaker("tool_a")

        # tool_b should still work
        result = gateway.check_circuit_breaker("tool_b")
        assert result is None

    def test_old_entries_pruned(self) -> None:
        """Test that old entries are pruned after window expires."""
        # Make max calls
        for _ in range(gateway.MAX_CALLS_PER_TOOL):
            gateway.check_circuit_breaker("test_tool")

        # Verify blocked
        assert gateway.check_circuit_breaker("test_tool") is not None

        # Simulate time passing by manipulating the tracker
        old_time = datetime.datetime.now() - datetime.timedelta(
            seconds=gateway.CALL_WINDOW_SECONDS + 1
        )
        gateway.TOOL_CALL_TRACKER["test_tool"] = [old_time] * gateway.MAX_CALLS_PER_TOOL

        # Now should be allowed again (old entries pruned)
        result = gateway.check_circuit_breaker("test_tool")
        assert result is None

    def test_disabled_circuit_breaker(self) -> None:
        """Test that disabled circuit breaker allows all calls."""
        original = gateway.CIRCUIT_BREAKER_ENABLED
        try:
            gateway.CIRCUIT_BREAKER_ENABLED = False

            # Make way more than max calls
            for _ in range(gateway.MAX_CALLS_PER_TOOL * 2):
                result = gateway.check_circuit_breaker("test_tool")
                assert result is None
        finally:
            gateway.CIRCUIT_BREAKER_ENABLED = original


class TestCheckAllPolicies:
    """Tests for the check_all_policies function."""

    def setup_method(self) -> None:
        """Reset state before each test."""
        gateway.TOOL_CALL_TRACKER.clear()

    def test_non_tools_call_passes(self) -> None:
        """Test non-tools/call messages pass through."""
        message = {"method": "initialize", "id": "init-001"}
        result = gateway.check_all_policies(message)
        assert result is None

    def test_circuit_breaker_checked_after_policy(self) -> None:
        """Test that circuit breaker is checked after policy passes."""
        # Import and configure policy
        import policy
        policy.CURRENT_POLICY = {"rules": []}

        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-001",
            "params": {
                "name": "test_tool",
                "arguments": {}
            }
        }

        # Fill up the circuit breaker
        for _ in range(gateway.MAX_CALLS_PER_TOOL):
            gateway.check_circuit_breaker("test_tool")

        # Now check_all_policies should block
        result = gateway.check_all_policies(message)
        assert result is not None
        assert "Circuit Breaker" in result

    def test_policy_block_takes_precedence(self) -> None:
        """Test that policy blocks before circuit breaker check."""
        import policy
        policy.CURRENT_POLICY = {
            "rules": [
                {
                    "name": "Block All",
                    "target_tool": "*",
                    "target_argument": "query",
                    "conditions": [],
                    "action": "block"
                }
            ]
        }

        message = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": "test-001",
            "params": {
                "name": "any_tool",
                "arguments": {"query": "anything"}
            }
        }

        result = gateway.check_all_policies(message)
        assert result == "Block All"
        # Circuit breaker should not have been called (no tracker entry)
        assert "any_tool" not in gateway.TOOL_CALL_TRACKER


class TestLogSecurityEvent:
    """Tests for the log_security_event function."""

    def test_log_creates_entry(self, tmp_path) -> None:
        """Test that security events are logged correctly."""
        log_file = tmp_path / "test_audit.log"
        original = gateway.AUDIT_LOG_FILE

        try:
            gateway.AUDIT_LOG_FILE = str(log_file)

            message = {
                "id": "test-log-001",
                "method": "tools/call",
                "params": {"name": "dangerous_tool"}
            }
            gateway.log_security_event(message, "Test Block Reason")

            # Verify log was written
            assert log_file.exists()
            content = log_file.read_text()
            assert "test-log-001" in content
            assert "Test Block Reason" in content
            assert "dangerous_tool" in content
        finally:
            gateway.AUDIT_LOG_FILE = original

    def test_log_appends(self, tmp_path) -> None:
        """Test that multiple events are appended."""
        log_file = tmp_path / "test_audit.log"
        original = gateway.AUDIT_LOG_FILE

        try:
            gateway.AUDIT_LOG_FILE = str(log_file)

            gateway.log_security_event({"id": "1", "method": "m"}, "First")
            gateway.log_security_event({"id": "2", "method": "m"}, "Second")

            content = log_file.read_text()
            lines = content.strip().split("\n")
            assert len(lines) == 2
        finally:
            gateway.AUDIT_LOG_FILE = original
