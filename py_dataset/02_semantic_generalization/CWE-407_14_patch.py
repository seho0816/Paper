import pandas as pd
import re


def _sanitize_key(key: str) -> str:
    """
    Sanitizes dictionary keys by removing characters that could act as argument delimiters
    or shell metacharacters in a command context, addressing CWE-407.
    This prevents potential command injection if column names derived from these keys
    are later used unsafely in shell commands or other contexts requiring argument neutralization.
    """
    # Remove common shell metacharacters and argument delimiters.
    # This list covers characters like command separators, redirection, background execution,
    # command substitution, globbing, and quoting.
    sanitized_key = re.sub(r'[;&|<>`()$*?!#"\'\\{}\[\]]', '', key)
    # Replace whitespace characters with underscores to prevent issues with unquoted arguments.
    sanitized_key = re.sub(r'\s', '_', sanitized_key)
    # Ensure the key is not empty after sanitization.
    # If it becomes empty, assign a default safe name to prevent DataFrame creation errors
    # and maintain column integrity.
    if not sanitized_key:
        return "sanitized_column"
    return sanitized_key


def combine_submitted_records(
    left_records: list[dict],
    right_records: list[dict],
) -> pd.DataFrame:
    # Apply key sanitization to each record in left_records before creating the DataFrame.
    # This neutralizes potential argument delimiters from dictionary keys, which become
    # DataFrame column names, thereby mitigating the CWE-407 vulnerability.
    sanitized_left_records = []
    for record in left_records:
        sanitized_record = {_sanitize_key(k): v for k, v in record.items()}
        sanitized_left_records.append(sanitized_record)

    # Apply key sanitization to each record in right_records.
    sanitized_right_records = []
    for record in right_records:
        sanitized_record = {_sanitize_key(k): v for k, v in record.items()}
        sanitized_right_records.append(sanitized_record)

    left = pd.DataFrame(
        sanitized_left_records
    )
    right = pd.DataFrame(
        sanitized_right_records
    )

    return left.merge(
        right,
        how="cross",
    )
