from simpleeval import SimpleEval, simple_eval


def evaluate_access_rule(
    expression: str,
    context: dict,
):
    # CWE-917 mitigation: Improper Neutralization of Special Elements used in an Expression Language Statement.
    # The simple_eval library is generally safer than Python's built-in eval(),
    # as it disallows attribute access (e.g., obj.method) and arbitrary function calls by default.
    # However, to enhance security for evaluating "access rules" and prevent potential resource exhaustion (DoS)
    # or unintended complex evaluations, we explicitly configure the SimpleEval instance.

    # 1. Restrict allowed functions:
    #    The default simple_eval provides a set of built-in functions (like range, list, dict, sum).
    #    For access rules, a more restrictive whitelist of functions reduces the attack surface
    #    and prevents expressions from performing complex or resource-intensive operations beyond
    #    the scope of typical access checks.
    #    Only commonly needed functions for boolean logic, length checks, and type conversions are allowed.
    allowed_functions = {
        'len': len,    # Useful for checking length of lists, strings.
        'str': str,    # For type conversions to string.
        'int': int,    # For type conversions to integer.
        'float': float,  # For type conversions to float.
        'bool': bool,  # For type conversions to boolean.
    }

    # 2. Limit execution steps:
    #    Setting 'max_steps' prevents Denial of Service (DoS) attacks by crafting overly complex
    #    or long-running expressions that consume excessive CPU cycles.
    #    A value of 5000 is chosen as a reasonable limit for access rule evaluations.

    # 3. Explicitly disallow getattr and getitem (though they are False by default in simpleeval):
    #    This reinforces the prevention of attribute access (e.g., 'obj.attr') and item access
    #    (e.g., 'obj[index]' on arbitrary objects), which are common vectors for EL injection.

    evaluator = SimpleEval(
        names=context,
        functions=allowed_functions,
        max_steps=5000,
        disallow_getattr=True,
        disallow_getitem=True,
    )

    return evaluator.eval(expression)
