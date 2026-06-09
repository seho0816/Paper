def _sanitize_nosql_selector_strict(selector_input: dict) -> dict:
    """
    Recursively sanitizes a dictionary intended for NoSQL queries to prevent injection.
    This function strictly disallows any key that starts with '$' (common NoSQL operators)
    at any level of nesting. If the application *needs* to support specific operators,
    this function would require modification to whitelist those operators.
    """
    sanitized_selector = {}
    for key, value in selector_input.items():
        if isinstance(key, str) and key.startswith('$'):
            # Disallow keys that start with '$' as these typically represent NoSQL operators
            # and could be used for injection if not explicitly allowed and validated.
            raise ValueError(f"Disallowed NoSQL operator key found: {key}")

        if isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            sanitized_selector[key] = _sanitize_nosql_selector_strict(value)
        elif isinstance(value, list):
            # Recursively sanitize items in lists if they are dictionaries
            sanitized_list = []
            for item in value:
                if isinstance(item, dict):
                    sanitized_list.append(_sanitize_nosql_selector_strict(item))
                else:
                    # Keep non-dict items as is
                    sanitized_list.append(item)
            sanitized_selector[key] = sanitized_list
        else:
            # Simple scalar value, safe
            sanitized_selector[key] = value
    return sanitized_selector


def resolve_search_documents(
    _root,
    info,
    selector: dict,
) -> list[dict]:
    # Sanitize the selector input to prevent NoSQL injection.
    # This ensures that no malicious operator keys (e.g., "$where", "$gt")
    # are passed directly to the database query logic.
    safe_selector = _sanitize_nosql_selector_strict(selector)

    return list(
        info.context.documents.find(
            safe_selector
        )
    )
