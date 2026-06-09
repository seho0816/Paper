import re

def read_json_value(
    redis_client,
    document_key: str,
    submitted_path: str,
):
    # CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    # Validate the submitted_path to prevent NoSQL injection vulnerabilities
    # in RedisJSON path expressions. This regex strictly whitelists allowed
    # characters and patterns, disallowing potentially malicious constructs
    # such as wildcards (*), recursive descent (..), and complex filter expressions
    # (e.g., [?(...)]) which could lead to information disclosure or DoS.
    #
    # The allowed path pattern must:
    # - Start with '$' (representing the root of the JSON document).
    # - Be followed by zero or more segments.
    # - Each segment can be either:
    #     - A dot ('.') followed by one or more alphanumeric characters or underscores
    #       (e.g., '.field_name').
    #     - Square brackets '[]' containing one or more digits (e.g., '[0]' for array indices).
    # This pattern ensures only direct field access and array indexing are permitted.
    # An empty submitted_path or paths starting with only `$` without further valid segments
    # will be rejected if the intent is to access nested data; if `$` alone is a valid
    # access to the root, the regex still matches it.
    
    SAFE_REDISJSON_PATH_PATTERN = re.compile(r"^\$(?:\.[a-zA-Z0-9_]+|\[\d+\])*$")

    if not SAFE_REDISJSON_PATH_PATTERN.match(submitted_path):
        raise ValueError("Invalid RedisJSON path detected. Path must adhere to a safe pattern.")

    return redis_client.json().get(
        document_key,
        submitted_path,
    )
