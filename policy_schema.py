"""
Policy Schema Validation for MCP Sentinel using Pydantic.

Defines Pydantic models for validating security policy YAML files.
"""

from typing import Literal

from pydantic import BaseModel, Field, ValidationError

VALID_OPERATORS = {"contains", "not_contains", "equals", "regex"}
VALID_ACTIONS = {"block", "allow", "log", "allow_with_approval"}
VALID_MATCH_TYPES = {"all", "any"}


class Condition(BaseModel):
    """A single condition to evaluate against a tool argument."""

    operator: Literal["contains", "not_contains", "equals", "regex"]
    value: str
    ignore_case: bool = False


class Rule(BaseModel):
    """A security rule that matches tool calls and applies an action."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    target_tool: str
    target_argument: str
    conditions: list[Condition] = Field(default_factory=list)
    match_type: Literal["all", "any"] = "all"
    action: Literal["block", "allow", "log", "allow_with_approval"] = "block"


class Policy(BaseModel):
    """Root policy object containing a list of rules."""

    rules: list[Rule] = Field(default_factory=list)


class PolicyValidationError(Exception):
    """Raised when policy validation fails."""

    pass


def validate_policy(policy_dict: dict) -> list[str]:
    """
    Validate entire policy structure using Pydantic.

    Args:
        policy_dict: Raw policy dictionary loaded from YAML

    Returns:
        List of error messages (empty if valid)
    """
    try:
        Policy.model_validate(policy_dict)
        return []
    except ValidationError as e:
        # Convert Pydantic errors to simple strings
        errors = []
        for err in e.errors():
            loc = " -> ".join(str(loc_part) for loc_part in err["loc"])
            msg = err["msg"]
            errors.append(f"{loc}: {msg}")
        return errors


def validate_policy_or_raise(policy_dict: dict) -> None:
    """
    Validate policy and raise PolicyValidationError if invalid.

    Args:
        policy_dict: Raw policy dictionary loaded from YAML

    Raises:
        PolicyValidationError: If validation fails
    """
    errors = validate_policy(policy_dict)
    if errors:
        raise PolicyValidationError("\n".join(errors))
