import rule_engine
import re


def select_accounts(
    expression: str,
    accounts: list[dict],
) -> list[dict]:
    # CWE-917 mitigation: Improper Neutralization of Special Elements used in an Expression Language Statement.
    # The 'expression' input is user-controlled and passed directly to rule_engine.Rule().
    # While rule_engine has its own domain-specific language and is not a full Python interpreter,
    # attackers might attempt to inject "special elements" (e.g., Python introspection or execution keywords)
    # that could potentially exploit unforeseen vulnerabilities, cause parsing errors, or consume excessive resources.
    # This patch neutralizes such attempts by proactively removing commonly exploited "special elements"
    # from the expression string. These patterns are not part of legitimate rule_engine syntax,
    # so their removal does not break intended functionality.

    sanitized_expression = expression

    # Define a list of regex patterns for "special elements" that should be neutralized.
    # These include Python-specific introspection/execution keywords and module accesses
    # that are typically targeted in Expression Language Injection attacks.
    # We use word boundaries (\b) to avoid false positives on parts of legitimate words or keys.
    # The patterns are case-insensitive.
    dangerous_patterns = [
        # Python execution/introspection functions/keywords
        r'\b(?:eval|exec|compile|open|system|breakpoint)\b',
        r'\b(?:__import__)\b',
        r'\b(?:__class__|__bases__|__subclasses__|__globals__|__builtins__)\b',
        # Access to sensitive modules/objects (e.g., os.system)
        r'\b(?:os\s*\.|subprocess\s*\.|sys\s*\.|inspect\s*\.)\b',
        # Attempts to access dunder methods as dictionary keys or attributes
        # This is a heuristic: if a legitimate dictionary key or attribute is named exactly like this,
        # it might be affected. However, for security, preventing access to such potentially
        # exploitable patterns is often prioritized, as legitimate data should ideally not
        # use these names in a user-controlled expression context.
        r"['\"]__\w+__['\"]", # e.g., ['__class__'] or "__init__" as string literals
        r"\.__\w+__\b",        # e.g., .__class__ for attribute-like access
    ]

    for pattern in dangerous_patterns:
        # Replace detected dangerous patterns with an empty string to neutralize them.
        # This effectively removes the "special elements" from the input.
        sanitized_expression = re.sub(pattern, '', sanitized_expression, flags=re.IGNORECASE)

    # Create the rule engine with the sanitized expression.
    rule = rule_engine.Rule(
        sanitized_expression
    )

    return [
        account
        for account in accounts
        if rule.matches(
            account
        )
    ]
