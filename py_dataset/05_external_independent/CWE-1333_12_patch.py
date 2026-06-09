import pandas as pd
import re


def filter_rows(
    frame: pd.DataFrame,
    user_pattern: str,
) -> pd.DataFrame:
    # CWE-1333: Inefficient Regular Expression Complexity (ReDoS)
    # The original code directly uses 'user_pattern' as a regular expression.
    # If 'user_pattern' is provided by an untrusted source, a maliciously crafted
    # regex could lead to catastrophic backtracking, causing a Denial of Service (DoS).
    #
    # To mitigate this, 're.escape()' is used to escape any special regular expression
    # characters in 'user_pattern'. This ensures that the pattern is treated as a
    # literal string for matching, preventing it from being interpreted as a complex
    # or malicious regular expression that could trigger ReDoS.
    # This change secures the function against ReDoS while maintaining the ability
    # to search for specific literal strings that might contain regex-like characters.
    safe_pattern = re.escape(user_pattern)

    matches = frame[
        "message"
    ].str.contains(
        safe_pattern,  # Use the escaped pattern to prevent ReDoS
        regex=True,
        na=False,
    )

    return frame[matches]
