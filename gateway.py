import sys
import json
import logging
import subprocess
import threading
import datetime

# Konfiguracja kolorów dla terminala
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def log_to_stderr(message: str, color: str = ""):
    """Log colored messages to stderr, keeping stdout clean for JSON-RPC"""
    sys.stderr.write(f"{color}{message}{RESET}\n")
    sys.stderr.flush()

def is_dangerous(message: dict) -> bool:
    """Prosta logika wykrywania Data Exfiltration (brak LIMIT w SQL)"""
    try:
        if message.get("method") == "tools/call":
            params = message.get("params", {})
            args = params.get("arguments", {})

            # Symulacja: Sprawdzamy czy to zapytanie SQL
            if "query" in args:
                query = args["query"].upper()
                # Jeśli jest SELECT, a nie ma LIMIT -> BLOKADA
                if "SELECT" in query and "LIMIT" not in query:
                    return True
    except Exception:
        pass
    return False

def log_security_event(message: dict, reason: str):
    """Append blocked requests to security_audit.log"""
    timestamp = datetime.datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "message_id": message.get("id"),
        "method": message.get("method"),
        "reason": reason,
        "details": message
    }
    with open("security_audit.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def spawn_mcp_server(args: list) -> subprocess.Popen:
    """Spawn the wrapped MCP server as subprocess"""
    log_to_stderr(f"[STARTUP] Spawning MCP server: {' '.join(args)}", YELLOW)

    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    # Forward server stderr in background
    def forward_stderr():
        for line in process.stderr:
            log_to_stderr(f"[SERVER STDERR] {line.rstrip()}", YELLOW)

    threading.Thread(target=forward_stderr, daemon=True).start()

    return process

def forward_client_to_server(stdin_stream, server_stdin, stop_event):
    """Read from client stdin, validate, forward to server or inject error"""
    try:
        for line in stdin_stream:
            if stop_event.is_set():
                break

            try:
                message = json.loads(line)

                # Only validate tools/call messages
                if message.get("method") == "tools/call" and is_dangerous(message):
                    # Block and log
                    log_to_stderr(f"[BLOCK] Request ID: {message.get('id')}", RED)
                    log_security_event(message, "Data Exfiltration Prevention")

                    # Inject error response to stdout
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32000,
                            "message": "Policy Violation: Unbounded Query"
                        }
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

def forward_server_to_client(server_stdout, stdout_stream, stop_event):
    """Read from server stdout, forward to client stdout (no validation)"""
    try:
        for line in server_stdout:
            if stop_event.is_set():
                break

            # Pass through all responses
            stdout_stream.write(line)
            stdout_stream.flush()
    except:
        pass  # Client disconnected

def run_demo_mode():
    """Legacy demo mode: read single message from stdin, validate, print result"""
    log_to_stderr("[DEMO MODE] Reading single message from stdin...", YELLOW)

    input_data = sys.stdin.read()

    try:
        message = json.loads(input_data)
        log_to_stderr(f"[INFO] Intercepting MCP Request ID: {message.get('id')}...", YELLOW)

        if is_dangerous(message):
            log_to_stderr("[SECURITY ALERT] MCP GUARDRAIL TRIGGERED!", RED)
            log_to_stderr("[BLOCK] Reason: Data Exfiltration Prevention Policy.", RED)
            log_security_event(message, "Data Exfiltration Prevention (Demo)")

            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32000, "message": "Policy Violation: Unbounded Query"}
            }
            print(json.dumps(error_response, indent=2))
        else:
            log_to_stderr("[PASS] Request validated. Would forward to server.", GREEN)

    except json.JSONDecodeError:
        log_to_stderr("[ERROR] Invalid JSON input", RED)

def main():
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
        args=(sys.stdin, server_process.stdin, stop_event)
    )

    server_thread = threading.Thread(
        target=forward_server_to_client,
        args=(server_process.stdout, sys.stdout, stop_event)
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