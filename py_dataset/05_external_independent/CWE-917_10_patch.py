import re

def resolve_calculate(
    _root,
    info,
    expression: str,
) -> dict:
    # CWE-917: Improper Neutralization of Expression Language Constructs in an EL Context ('Expression Language Injection')
    # The 'expression' parameter is directly passed to an evaluation engine,
    # which can lead to code injection if not properly sanitized.
    # To mitigate, we validate the input 'expression' string using a strict whitelist.

    # This regex ensures that the expression only contains safe constructs for
    # basic mathematical operations and variable access.
    # It allows:
    #   1. Valid Python-style identifiers (for variable names): `[a-zA-Z_][a-zA-Z0-9_]*`
    #   2. Numbers (integers or floats): `\d+(?:\.\d*)?` (e.g., 123, 123.45, 123.) or `\.\d+` (e.g., .45)
    #   3. Basic arithmetic operators: `[+\-*/%]`
    #   4. Parentheses: `[()]`
    #   5. Whitespace: `\s+`
    # Any other characters or patterns (like square brackets, quotes, semicolons,
    # or multiple dots for attribute chaining) will cause the validation to fail,
    # preventing injection of malicious code.
    SAFE_EXPRESSION_PATTERN = re.compile(
        r"^(?:[a-zA-Z_][a-zA-Z0-9_]*|\d+(?:\.\d*)?|\.\d+|[+\-*/%()]|\s+)+$"
    )

    if not SAFE_EXPRESSION_PATTERN.fullmatch(expression):
        raise ValueError("Invalid characters or unsafe constructs detected in expression.")

    result = info.context.expression_engine.evaluate(
        expression,
        info.context.variables,
    )

    return {
        "result": result,
    }
