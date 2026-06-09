from dataclasses import dataclass
import ast

# Define allowed AST node types. This list is crucial for security. Be very conservative.
# It should allow basic literals, variable access, and common arithmetic/logical operations.
# It must *explicitly exclude* any node type that could lead to arbitrary code execution or side effects.
_ALLOWED_AST_NODE_TYPES = (
    ast.Expression,  # The top-level wrapper for an expression (required for mode='eval')
    ast.Constant,    # Literal values (numbers, strings, booleans, None)
    ast.Name,        # Variable names (e.g., 'x', 'y', 'variables')
    ast.Load,        # Context for loading a name (used with ast.Name)
    ast.BinOp,       # Binary operations (e.g., +, -, *, /)
    ast.UnaryOp,     # Unary operations (e.g., -, not)
    ast.Compare,     # Comparison operations (e.g., ==, <, >)
    ast.BoolOp,      # Boolean operations (e.g., and, or)
    ast.IfExp,       # Ternary operator (e.g., 'a if b else c')
    ast.List,        # List literals [1, 2, 3]
    ast.Tuple,       # Tuple literals (1, 2, 3)
    ast.Set,         # Set literals {1, 2, 3}
    ast.Dict,        # Dictionary literals {'a': 1, 'b': 2}
    ast.Subscript,   # Subscripting (e.g., variables['key']) - crucial for accessing dicts
    ast.Index,       # Index within a subscript (e.g., 'key' in variables['key'])
    ast.Slice,       # Slicing within a subscript (e.g., list[1:5])
)


def _validate_safe_expression(expression: str) -> None:
    """
    Parses a string as a Python expression and validates its Abstract Syntax Tree (AST)
    to ensure it only contains safe, allowed constructs. This prevents Expression Language
    Injection by disallowing potentially malicious operations.

    Raises ValueError if the expression has invalid syntax or contains unsafe constructs.
    """
    try:
        # Use mode='eval' to parse the string as a single expression.
        # This inherently prevents the parsing of arbitrary statements like 'import os'
        # or 'def malicious_func(): ...' as these are not single expressions.
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        # The expression itself is not well-formed Python syntax.
        raise ValueError(f"Invalid expression syntax: {e}") from e

    # Walk the AST and check each node against the whitelist of allowed types.
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_AST_NODE_TYPES):
            # If any node is not in the whitelist, it's considered an unsafe construct.
            # This includes function calls (ast.Call), attribute access (ast.Attribute),
            # lambda functions (ast.Lambda), comprehensions, etc., which are all potentially
            # dangerous if the interpreter is an unsafe evaluator like Python's built-in `eval`.
            raise ValueError(
                f"Unsafe construct '{type(node).__name__}' found in expression. "
                "Only safe literals, variable access, and basic operations are allowed."
            )


# Placeholder for database interactions. In a real application, this would be a secure data source.
# We keep this as a conceptual class to maintain the original code's structure for loading rules.
class database:
    @staticmethod
    def load_rule(rule_id: str) -> str:
        # This is a placeholder. In a real application, rules would be loaded
        # from a secure, trusted data store. For demonstration purposes,
        # we return a simple expression string.
        return f"rule_{rule_id}_value > 10 and variables['status'] == 'active'"


@dataclass(frozen=True)
class StoredRule:
    expression: str


class RuleRepository:
    def find(
        self,
        rule_id: str,
    ) -> StoredRule:
        return StoredRule(
            expression=database.load_rule(
                rule_id
            )
        )


class RuleService:
    def __init__(
        self,
        repository: RuleRepository,
        interpreter,
    ) -> None:
        self._repository = repository
        self._interpreter = interpreter

    def evaluate(
        self,
        rule_id: str,
        variables: dict,
    ):
        rule = self._repository.find(
            rule_id
        )

        # CWE-917 fix: Validate the expression from the database before passing it
        # to the interpreter. This prevents Expression Language Injection by ensuring
        # the expression does not contain any unsafe Python constructs that could
        # lead to arbitrary code execution, regardless of how 'self._interpreter'
        # internally handles expressions.
        _validate_safe_expression(rule.expression)

        return self._interpreter(
            rule.expression,
            variables,
        )
