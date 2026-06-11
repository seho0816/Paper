import re


def wildcard_search(
    wildcard: str,
    values: list[str],
) -> list[str]:
    # CWE-1333: Inefficient Regular Expression Complexity (ReDoS) mitigation
    # 1. Escape all regex special characters in the wildcard string.
    #    This ensures that user-provided characters like '.', '+', '?', etc.,
    #    are treated as literals and do not introduce unexpected regex behavior.
    # 2. Replace the escaped glob wildcard '\*' with a non-greedy regex equivalent '.*?'
    #    Using '.*?' (non-greedy) instead of '.*' (greedy) helps mitigate
    #    catastrophic backtracking issues that arise from repeated greedy quantifiers
    #    in certain patterns, preventing ReDoS.
    pattern_text = re.escape(wildcard).replace(
        r"\*",
        ".*?",
    )
    pattern = re.compile(
        "^" + pattern_text + "$"
    )

    return [
        value
        for value in values
        if pattern.match(value)
    ]
