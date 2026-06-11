import copy

def search_accounts(
    collection,
    submitted_filter: dict,
) -> list[dict]:
    
    # Create a deep copy of the submitted filter to avoid modifying the original
    # and to allow recursive sanitization without side effects.
    sanitized_filter = copy.deepcopy(submitted_filter)

    # Recursively sanitize the dictionary to remove any keys that resemble NoSQL operators.
    # NoSQL operators often start with '$' or, less commonly, '_'.
    # This prevents NoSQL injection (CWE-943).
    def _recursively_sanitize_mongo_query(obj):
        if isinstance(obj, dict):
            keys_to_remove = []
            for key, value in obj.items():
                if isinstance(key, str) and (key.startswith('$') or key.startswith('_')):
                    keys_to_remove.append(key)
                else:
                    obj[key] = _recursively_sanitize_mongo_query(value)
            for key in keys_to_remove:
                del obj[key]
        elif isinstance(obj, list):
            obj[:] = [_recursively_sanitize_mongo_query(item) for item in obj]
        return obj

    # Apply the sanitization to the filter before passing it to the database query.
    cleaned_filter = _recursively_sanitize_mongo_query(sanitized_filter)

    return list(
        collection.find(
            cleaned_filter
        )
    )
