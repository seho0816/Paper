import ast

def calculate_price(
    expression_engine,
    pricing_rule: str,
    variables: dict,
):
    # CWE-917: Improper Neutralization of Expression Language Constructs in an EL Expression (Expression Language Injection)
    # The vulnerability occurs if `pricing_rule` can contain arbitrary code that `expression_engine` executes.
    # To mitigate this without modifying the `expression_engine` itself, we must validate `pricing_rule`
    # to ensure it only contains safe constructs before evaluation.

    try:
        # Parse the pricing_rule into an Abstract Syntax Tree (AST).
        # Use mode='eval' to ensure the input is a single expression, not a sequence of statements.
        tree = ast.parse(pricing_rule, mode='eval')
    except SyntaxError as e:
        # If the expression is not syntactically valid Python, raise an error.
        raise ValueError(f"Invalid pricing rule syntax: {e}")

    # Whitelist of allowed AST node types. This list permits simple literals,
    # variable names, and basic arithmetic, logical, and comparison operations.
    # Any node type not in this whitelist is considered potentially unsafe.
    ALLOWED_NODE_TYPES = (
        ast.Expression,    # The root node for expressions in 'eval' mode.
        ast.Name,          # Represents a variable name (e.g., 'price', 'quantity').
        ast.Constant,      # Represents a literal constant (numbers, strings, True, False, None).
        ast.UnaryOp,       # Represents a unary operation (e.g., -x, not x).
        ast.BinOp,         # Represents a binary operation (e.g., x + y, x * y).
        ast.BoolOp,        # Represents a boolean operation (e.g., x and y, x or y).
        ast.Compare,       # Represents a comparison operation (e.g., x == y, x > y).
    )

    for node in ast.walk(tree):
        # Check if the current AST node type is in the whitelist.
        if not isinstance(node, ALLOWED_NODE_TYPES):
            # If an unallowed node type is found (e.g., ast.Call, ast.Attribute, ast.Subscript, ast.Lambda),
            # it indicates an attempt to execute arbitrary code or access restricted resources.
            raise ValueError(f"Disallowed construct '{type(node).__name__}' found in pricing rule.")

        # For nodes representing variable names, ensure they are explicitly provided in the `variables` dictionary.
        # This prevents access to global context, built-ins, or other objects not intended for the expression.
        if isinstance(node, ast.Name):
            if node.id not in variables:
                raise ValueError(f"Undefined variable '{node.id}' in pricing rule.")

    # If the expression passes all validation checks, it is deemed safe to evaluate.
    return expression_engine.evaluate(
        pricing_rule,
        variables,
    )
