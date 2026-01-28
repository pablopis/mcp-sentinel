"""
Policy loading and evaluation for MCP Sentinel.

Handles YAML policy file loading, condition checking, and rule evaluation
against incoming JSON-RPC messages.
"""

import fnmatch
import os
import re
import signal
from typing import Callable

import yaml

from policy_schema import validate_policy

# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Resolve paths relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY_FILE = os.path.join(SCRIPT_DIR, "security_policy.yaml")

# Current loaded policy (mutable global state)
CURRENT_POLICY: dict = {}

# Logger function (will be set by gateway)
_log_fn: Callable[[str, str], None] | None = None


def set_logger(log_fn: Callable[[str, str], None]) -> None:
    """Set the logging function to use for policy messages."""
    global _log_fn
    _log_fn = log_fn


def _log(message: str, color: str = "") -> None:
    """Log a message using the configured logger."""
    if _log_fn:
        _log_fn(message, color)


def load_policy(policy_path: str | None = None) -> dict:
    """
    Load security policy from YAML file with validation.

    Args:
        policy_path: Path to policy YAML file. Defaults to security_policy.yaml

    Returns:
        Policy dictionary with 'rules' key, or empty rules on error
    """
    if policy_path is None:
        policy_path = os.environ.get("MCP_POLICY_FILE", DEFAULT_POLICY_FILE)

    try:
        with open(policy_path, "r") as f:
            policy = yaml.safe_load(f)

            # Validate schema
            errors = validate_policy(policy)
            if errors:
                for error in errors:
                    _log(f"[POLICY ERROR] {error}", RED)
                _log(
                    f"[WARNING] Policy has {len(errors)} validation errors. Defaulting to empty.",
                    YELLOW,
                )
                return {"rules": []}

            _log(f"[INIT] Loaded policy with {len(policy.get('rules', []))} rules", GREEN)
            return policy
    except FileNotFoundError:
        _log(f"[WARNING] Policy file {policy_path} not found. Defaulting to open access.", YELLOW)
        return {"rules": []}
    except Exception as e:
        _log(f"[ERROR] Failed to load policy: {e}", RED)
        return {"rules": []}


def init_policy(policy_path: str | None = None) -> None:
    """
    Initialize the global CURRENT_POLICY.

    Args:
        policy_path: Optional path to policy file
    """
    global CURRENT_POLICY
    CURRENT_POLICY = load_policy(policy_path)


def reload_policy_handler(signum: int, frame: object) -> None:
    """SIGHUP handler to reload policy without restart."""
    global CURRENT_POLICY
    _log("[RELOAD] Received SIGHUP, reloading policy...", YELLOW)
    CURRENT_POLICY = load_policy()


def register_sighup_handler() -> None:
    """Register SIGHUP handler for policy hot-reload (Unix only)."""
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_policy_handler)
        _log("[INIT] SIGHUP handler registered for policy hot-reload", GREEN)


def check_condition(value: str, condition: dict) -> bool:
    """
    Evaluate a single condition against a value.

    Args:
        value: The string value to check (e.g., SQL query)
        condition: Dict with 'operator', 'value', and optional 'ignore_case'

    Returns:
        True if condition matches, False otherwise
    """
    op = condition.get("operator")
    target = condition.get("value")
    ignore_case = condition.get("ignore_case", False)

    # For regex, use re.IGNORECASE flag instead of uppercasing
    # (uppercasing breaks regex special sequences like \s -> \S)
    if op != "regex" and ignore_case and isinstance(value, str):
        value = value.upper()
        target = target.upper() if target else target

    match op:
        case "contains":
            return target in value
        case "not_contains":
            return target not in value
        case "equals":
            return value == target
        case "regex":
            try:
                flags = re.IGNORECASE if ignore_case else 0
                # Compile regex first to catch invalid patterns
                pattern = re.compile(target, flags)
                # Limit input length to prevent ReDoS
                return bool(pattern.search(value[:10000]))
            except re.error as e:
                _log(f"[REGEX ERROR] Invalid pattern '{target}': {e}", RED)
                return False
        case _:
            return False


def evaluate_policy(message: dict) -> str | None:
    """
    Evaluate the message against the global CURRENT_POLICY.

    Args:
        message: JSON-RPC message dict

    Returns:
        - Rule name string if blocked
        - "HITL:<rule_name>" if approval required
        - None if allowed
    """
    if message.get("method") != "tools/call":
        return None

    params = message.get("params", {})
    tool_name = params.get("name")
    args = params.get("arguments", {})

    for rule in CURRENT_POLICY.get("rules", []):
        # 1. Check if tool matches (supports wildcards like "*" or "query_*")
        target_tool_pattern = rule.get("target_tool", "")
        if not fnmatch.fnmatch(tool_name or "", target_tool_pattern):
            continue

        # 2. Check if argument exists
        arg_name = rule.get("target_argument")
        if arg_name not in args:
            continue

        arg_value = args[arg_name]

        # 3. Check conditions
        conditions = rule.get("conditions", [])
        match_type = rule.get("match_type", "all")

        matches = [check_condition(arg_value, c) for c in conditions]

        # Determine if rule matches based on match_type
        if not matches:
            is_match = match_type == "all"  # Empty conditions: match if 'all', else fail
        else:
            is_match = all(matches) if match_type == "all" else any(matches)

        if is_match:
            action = rule.get("action", "block")
            match action:
                case "block":
                    return rule.get("name")
                case "allow_with_approval":
                    # Special return value to signal approval needed
                    return f"HITL:{rule.get('name')}"
                case "allow":
                    # Explicitly allow - stop processing rules, return None
                    return None
                case "log":
                    # Log but don't block - continue to next rule
                    _log(f"[LOG] Rule '{rule.get('name')}' matched (action=log)", YELLOW)
                    # Continue checking other rules

    return None


def is_dangerous(message: dict) -> str | None:
    """
    Wrapper to evaluate policy.

    Args:
        message: JSON-RPC message dict

    Returns:
        Rule name if blocked, None otherwise
    """
    return evaluate_policy(message)
