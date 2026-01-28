"""
Human-in-the-Loop (HITL) approval server for MCP Sentinel.

Provides a side-channel HTTP server for approving or denying
blocked requests that require human intervention.
"""

import datetime
import http.server
import socketserver
import threading
import time
import uuid
from typing import Callable

# HITL Configuration
HITL_PORT: int = 8888
HITL_TIMEOUT_SECONDS: int = 300  # 5 min default
HITL_SECRET: str = str(uuid.uuid4())  # Random token for authentication

# Pending request storage
PENDING_REQUESTS: dict[str, dict] = {}  # {id: {"status": "pending", ...}}
REQUESTS_LOCK = threading.Lock()

# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Logger function (will be set by gateway)
_log_fn: Callable[[str, str], None] | None = None


def set_logger(log_fn: Callable[[str, str], None]) -> None:
    """Set the logging function to use for HITL messages."""
    global _log_fn
    _log_fn = log_fn


def _log(message: str, color: str = "") -> None:
    """Log a message using the configured logger."""
    if _log_fn:
        _log_fn(message, color)


def configure(
    port: int | None = None,
    timeout_seconds: int | None = None,
) -> None:
    """
    Configure HITL settings.

    Args:
        port: HTTP server port for approval URLs
        timeout_seconds: How long to wait for approval before timing out
    """
    global HITL_PORT, HITL_TIMEOUT_SECONDS
    if port is not None:
        HITL_PORT = port
    if timeout_seconds is not None:
        HITL_TIMEOUT_SECONDS = timeout_seconds


class ApprovalHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP handler for approving/denying requests with token auth."""

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default HTTP logging to stderr."""
        pass

    def do_GET(self) -> None:
        """Handle GET requests for approve/deny actions."""
        global PENDING_REQUESTS
        try:
            path_parts = self.path.strip("/").split("/")
            if len(path_parts) != 3:
                self.send_error(404, "Invalid path. Expected: /<action>/<token>/<id>")
                return

            action, token, req_id = path_parts

            # Validate token
            if token != HITL_SECRET:
                self.send_error(403, "Invalid authentication token")
                _log(f"[HITL] Unauthorized access attempt with token: {token[:8]}...", RED)
                return

            with REQUESTS_LOCK:
                if req_id not in PENDING_REQUESTS:
                    self.send_error(404, "Request ID not found or expired")
                    return

                if action == "approve":
                    PENDING_REQUESTS[req_id]["status"] = "approved"
                    msg = "✅ Request APPROVED. You may close this tab."
                elif action == "deny":
                    PENDING_REQUESTS[req_id]["status"] = "denied"
                    msg = "❌ Request DENIED. You may close this tab."
                else:
                    self.send_error(400, "Invalid action. Use /approve/ or /deny/")
                    return

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            html = f"<html><body style='font-family:sans-serif;text-align:center;padding:50px;'><h1>{msg}</h1></body></html>"
            self.wfile.write(html.encode())

        except Exception as e:
            self.send_error(500, str(e))


def start_approval_server() -> None:
    """Start the background HTTP server for HITL approvals."""
    try:
        # Allow reusing address to avoid 'Address already in use' during rapid restarts
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("", HITL_PORT), ApprovalHandler)

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _log(f"[HITL] Approval server running on http://localhost:{HITL_PORT}", GREEN)
    except Exception as e:
        _log(f"[HITL] Failed to start approval server: {e}", RED)


def wait_for_approval(message: dict, rule_name: str) -> str | None:
    """
    Block waiting for user approval via HTTP side-channel.

    Args:
        message: The JSON-RPC message requiring approval
        rule_name: Name of the policy rule that triggered HITL

    Returns:
        None if approved, or error message string if denied/timed out
    """
    req_id = str(uuid.uuid4())
    start_time = time.time()

    with REQUESTS_LOCK:
        PENDING_REQUESTS[req_id] = {
            "status": "pending",
            "message": message,
            "rule": rule_name,
            "timestamp": datetime.datetime.now(),
        }

    approval_url = f"http://localhost:{HITL_PORT}/approve/{HITL_SECRET}/{req_id}"
    deny_url = f"http://localhost:{HITL_PORT}/deny/{HITL_SECRET}/{req_id}"

    _log(f"\n[HITL] 🛑 ACTION PAUSED by rule '{rule_name}'", YELLOW)
    _log(f"[HITL] Timeout: {HITL_TIMEOUT_SECONDS}s", YELLOW)
    _log(f"[HITL] Approve: {approval_url}", GREEN)
    _log(f"[HITL] Deny:    {deny_url}", RED)
    _log("[HITL] Waiting for approval...\n", YELLOW)

    try:
        # Wait loop with timeout
        while True:
            elapsed = time.time() - start_time
            if elapsed >= HITL_TIMEOUT_SECONDS:
                _log(f"[HITL] Request {req_id} TIMED OUT after {HITL_TIMEOUT_SECONDS}s", RED)
                return "Approval Timed Out"

            with REQUESTS_LOCK:
                status = PENDING_REQUESTS[req_id]["status"]

            if status == "approved":
                _log(f"[HITL] Request {req_id} APPROVED", GREEN)
                return None  # Proceed
            elif status == "denied":
                _log(f"[HITL] Request {req_id} DENIED", RED)
                return "User Denied Action"

            time.sleep(0.5)
    finally:
        # Cleanup: remove from pending requests (fixes memory leak)
        with REQUESTS_LOCK:
            PENDING_REQUESTS.pop(req_id, None)
