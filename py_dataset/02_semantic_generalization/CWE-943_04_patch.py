import copy

def _sanitize_mongo_query_fragment(query_fragment):
    """
    Recursively sanitizes a MongoDB query fragment to prevent NoSQL injection (CWE-943).
    This function removes any dictionary keys that start with '$' from the input fragment
    and its nested dictionaries/lists. This neutralizes the ability to inject MongoDB
    operators from untrusted input.
    """
    if isinstance(query_fragment, dict):
        sanitized_dict = {}
        for k, v in query_fragment.items():
            if k.startswith('$'):
                continue
            else:
                sanitized_dict[k] = _sanitize_mongo_query_fragment(v)
        return sanitized_dict
    elif isinstance(query_fragment, list):
        sanitized_list = []
        for item in query_fragment:
            sanitized_list.append(_sanitize_mongo_query_fragment(item))
        return sanitized_list
    else:
        return query_fragment


def aggregate_orders(
    collection,
    submitted_match: dict,
) -> list[dict]:
    # Sanitize the submitted_match dictionary to prevent NoSQL injection (CWE-943).
    # The vulnerability arises from directly using user-supplied dictionaries in
    # query logic, allowing attackers to inject MongoDB operators.
    # By creating a deep copy and then sanitizing it, we ensure the original input
    # is not modified and that all potentially malicious operators are removed.
    sanitized_match = _sanitize_mongo_query_fragment(copy.deepcopy(submitted_match))

    pipeline = [
        {
            "$match": sanitized_match,
        },
        {
            "$limit": 100,
        },
    ]

    return list(
        collection.aggregate(
            pipeline
        )
    )
