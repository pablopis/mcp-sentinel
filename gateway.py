import sys
import json
import logging

# Konfiguracja kolorów dla terminala
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

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

def main():
    # Czytamy input (symulacja strumienia od Agenta)
    input_data = sys.stdin.read()
    
    try:
        message = json.loads(input_data)
        print(f"{YELLOW}[INFO] Intercepting MCP Request ID: {message.get('id')}...{RESET}")
        
        if is_dangerous(message):
            print(f"{RED}[SECURITY ALERT] 🛡️ MCP GUARDRAIL TRIGGERED!{RESET}")
            print(f"{RED}[BLOCK] Reason: Data Exfiltration Prevention Policy.{RESET}")
            print(f"{RED}[DETAIL] Detected unbounded SQL SELECT query without LIMIT clause.{RESET}")
            print(f"{RED}[ACTION] Request dropped. Error returned to Agent.{RESET}")
            
            error_response = {
                "jsonrpc": "2.0", 
                "id": message.get("id"), 
                "error": {"code": -32000, "message": "Policy Violation: Unbounded Query"}
            }
        else:
            print(f"{GREEN}[PASS] Request validated. Forwarding to SQLite Server.{RESET}")

    except json.JSONDecodeError:
        print("Invalid JSON")

if __name__ == "__main__":
    main()