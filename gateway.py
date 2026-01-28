"""
MCP Sentinel - Runtime Security Gateway for Agentic AI.

Main entry point that provides:
- Subprocess management for wrapped MCP servers
- Bidirectional JSON-RPC message forwarding
- Circuit breaker for rate limiting
- Integration with policy and HITL modules
"""

import datetime
import json
import os
import subprocess
import sys
import threading
from typing import TextIO

import hitl
import policy

# Terminal color configuration
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Audit log configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_FILE = os.environ.get("MCP_AUDIT_LOG", os.path.join(SCRIPT_DIR, "security_audit.log"))

# Circuit breaker configuration
CIRCUIT_BREAKER_ENABLED = os.environ.get("MCP_CIRCUIT_BREAKER", "true").lower() == "true"
MAX_CALLS_PER_TOOL = int(os.environ.get("MCP_MAX_CALLS_PER_TOOL", "100"))
CALL_WINDOW_SECONDS = int(os.environ.get("MCP_CALL_WINDOW_SECONDS", "60"))
TOOL_CALL_TRACKER: dict[str, list[datetime.datetime]] = {}
TRACKER_LOCK = threading.Lock()


def log_to_stderr(message: str, color: str = "") -> None:
    """Log colored messages to stderr, keeping stdout clean for JSON-RPC."""
    sys.stderr.write(f"{color}{message}{RESET}\n")
    sys.stderr.flush()


def check_circuit_breaker(tool_name: str) -> str | None:
    """
    Check if tool has exceeded call rate limit.

    Args:
        tool_name: Name of the tool being called

    Returns:
        Error message if blocked, None otherwise
    """
    if not CIRCUIT_BREAKER_ENABLED:
        return None

    with TRACKER_LOCK:
        # Get current time inside lock to avoid race conditions
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(seconds=CALL_WINDOW_SECONDS)

        if tool_name not in TOOL_CALL_TRACKER:
            TOOL_CALL_TRACKER[tool_name] = []

        # Prune old entries
        TOOL_CALL_TRACKER[tool_name] = [
            ts for ts in TOOL_CALL_TRACKER[tool_name] if ts > cutoff
        ]

        # Check limit
        if len(TOOL_CALL_TRACKER[tool_name]) >= MAX_CALLS_PER_TOOL:
            return f"Circuit Breaker: {tool_name} exceeded {MAX_CALLS_PER_TOOL} calls in {CALL_WINDOW_SECONDS}s"

        # Record this call
        TOOL_CALL_TRACKER[tool_name].append(now)

    return None


def check_all_policies(message: dict) -> str | None:
    """
    Check both policy rules and circuit breaker.

    Args:
        message: JSON-RPC message dict

    Returns:
        Block reason if blocked, None otherwise
    """
    # First check policy rules
    policy_result = policy.evaluate_policy(message)
    if policy_result:
        # Check if it's a HITL request
        if policy_result.startswith("HITL:"):
            rule_name = policy_result.split(":", 1)[1]
            # This blocks until approved or denied
            denial_reason = hitl.wait_for_approval(message, rule_name)
            if denial_reason:
                return denial_reason
            # If approved (None returned), proceed to circuit breaker
        else:
            # Blocked normally
            return policy_result

    # Then check circuit breaker
    if message.get("method") == "tools/call":
        tool_name = message.get("params", {}).get("name", "unknown")
        circuit_result = check_circuit_breaker(tool_name)
        if circuit_result:
            return circuit_result

    return None


def log_security_event(message: dict, reason: str) -> None:
    """Append blocked requests to security_audit.log."""
    timestamp = datetime.datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "message_id": message.get("id"),
        "method": message.get("method"),
        "reason": reason,
        "details": message,
    }
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def spawn_mcp_server(args: list[str]) -> subprocess.Popen[str]:
    """
    Spawn the wrapped MCP server as subprocess.

    Args:
        args: Command line arguments to pass to the MCP server

    Returns:
        Popen object for the spawned process
    """
    log_to_stderr(f"[STARTUP] Spawning MCP server: {' '.join(args)}", YELLOW)

    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # Line buffered
    )

    # Forward server stderr in background
    def forward_stderr() -> None:
        if process.stderr:
            for line in process.stderr:
                log_to_stderr(f"[SERVER STDERR] {line.rstrip()}", YELLOW)

    threading.Thread(target=forward_stderr, daemon=True).start()

    return process


def forward_client_to_server(
    stdin_stream: TextIO,
    server_stdin: TextIO | None,
    stop_event: threading.Event,
) -> None:
    """Read from client stdin, validate, forward to server or inject error."""
    if server_stdin is None:
        return

    try:
        for line in stdin_stream:
            if stop_event.is_set():
                break

            try:
                message = json.loads(line)

                # Check all policies (rules + circuit breaker)
                block_reason = check_all_policies(message)
                if message.get("method") == "tools/call" and block_reason:
                    # Block and log
                    log_to_stderr(f"[BLOCK] Request ID: {message.get('id')}", RED)
                    log_security_event(message, block_reason)

                    # Inject error response to stdout
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32000,
                            "message": f"Policy Violation: {block_reason}",
                        },
                    }
                    sys.stdout.write(json.dumps(error_response) + "\n")
                    sys.stdout.flush()
                else:
                    # Pass through
                    server_stdin.write(line)
                    server_stdin.flush()

            except json.JSONDecodeError:
                # Invalid JSON - pass through (let server handle)
                server_stdin.write(line)
                server_stdin.flush()

    finally:
        server_stdin.close()


def forward_server_to_client(
    server_stdout: TextIO | None,
    stdout_stream: TextIO,
    stop_event: threading.Event,
) -> None:
    """Read from server stdout, forward to client stdout (no validation)."""
    if server_stdout is None:
        return

    try:
        for line in server_stdout:
            if stop_event.is_set():
                break

            # Pass through all responses
            stdout_stream.write(line)
            stdout_stream.flush()
    except (IOError, BrokenPipeError, OSError):
        pass  # Client disconnected or pipe broken


def run_demo_mode() -> None:
    """Legacy demo mode: read single message from stdin, validate, print result."""
    log_to_stderr("[DEMO MODE] Reading single message from stdin...", YELLOW)

    input_data = sys.stdin.read()

    try:
        message = json.loads(input_data)
        log_to_stderr(f"[INFO] Intercepting MCP Request ID: {message.get('id')}...", YELLOW)

        block_reason = policy.is_dangerous(message)
        if block_reason:
            if block_reason.startswith("HITL:"):
                rule_name = block_reason.split(":", 1)[1]
                denial_reason = hitl.wait_for_approval(message, rule_name)
                if denial_reason:
                    block_reason = denial_reason  # Now it's a real block
                else:
                    block_reason = None  # Approved!

        if block_reason:
            log_to_stderr("[SECURITY ALERT] MCP GUARDRAIL TRIGGERED!", RED)
            log_to_stderr(f"[BLOCK] Reason: {block_reason}", RED)
            log_security_event(message, f"{block_reason} (Demo)")

            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32000, "message": f"Policy Violation: {block_reason}"},
            }
            print(json.dumps(error_response, indent=2))
        else:
            log_to_stderr("[PASS] Request validated. Would forward to server.", GREEN)

    except json.JSONDecodeError:
        log_to_stderr("[ERROR] Invalid JSON input", RED)


def main() -> None:
    """Main entry point for MCP Sentinel gateway."""
    # Configure modules with the shared logger
    policy.set_logger(log_to_stderr)
    hitl.set_logger(log_to_stderr)

    # Configure HITL from environment
    hitl.configure(
        port=int(os.environ.get("MCP_HITL_PORT", "8888")),
        timeout_seconds=int(os.environ.get("MCP_HITL_TIMEOUT_SECONDS", "300")),
    )

    # Initialize policy
    policy.init_policy()
    policy.register_sighup_handler()

    # Start HITL Server
    hitl.start_approval_server()

    # Mode detection
    if len(sys.argv) < 2:
        # DEMO MODE: Single message from stdin (backward compatibility)
        run_demo_mode()
        return

    # PROXY MODE: Continuous streaming with subprocess
    server_args = sys.argv[1:]

    log_to_stderr("=" * 60, YELLOW)
    log_to_stderr("🛡️  MCP SENTINEL - RUNTIME SECURITY GATEWAY", YELLOW)
    log_to_stderr("=" * 60, YELLOW)

    # Spawn wrapped MCP server
    server_process = spawn_mcp_server(server_args)

    # Create stop event for thread coordination
    stop_event = threading.Event()

    # Start forwarding threads
    client_thread = threading.Thread(
        target=forward_client_to_server,
        args=(sys.stdin, server_process.stdin, stop_event),
    )

    server_thread = threading.Thread(
        target=forward_server_to_client,
        args=(server_process.stdout, sys.stdout, stop_event),
    )

    client_thread.start()
    server_thread.start()

    # Wait for process to exit
    try:
        server_process.wait()
    except KeyboardInterrupt:
        log_to_stderr("[SHUTDOWN] Received interrupt signal", YELLOW)
    finally:
        stop_event.set()
        server_process.terminate()
        server_process.wait(timeout=5)
        client_thread.join(timeout=2)
        server_thread.join(timeout=2)
        log_to_stderr("[SHUTDOWN] Gateway stopped", YELLOW)


if __name__ == "__main__":
    main()